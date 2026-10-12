# Copyright 2026 4Chains Inc. All rights reserved.
"""Closed-source build: the Python package compiled to native extension modules, so the
wheel carries no ``.py`` source (except package markers and the framework glue).

Used two ways:

- as a PEP 517 build backend (``build-backend = "closed_backend"``, ``backend-path``
  pointing here), which is how the distribution workflow builds every wheel with
  cibuildwheel; and
- from the command line: ``python packaging/closed/closed_backend.py --out dist``.

Steps: build the normal maturin wheel (the Rust core, ``tokenis._core``), unpack it,
compile every ``tokenis/**/*.py`` with Cython, delete the sources, rewrite the wheel
metadata (licence, project links, description) and repack with the interpreter's tags.
Compiling is a deterrent against casual reading, not encryption: native code can be
disassembled.

Compiler output is never echoed (it quotes source lines); set CLOSED_BUILD_DEBUG=1 on a
trusted machine to see it.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
#: Test modules that live inside the package; they are not shipped.
EXCLUDE = re.compile(r"(^|/)(test_[^/]*\.py|conftest\.py)$")
#: Package paths that are not shipped at all.
DROP_DIRS = ("tokenis/conformance", "tokenis/mcp_server/test_server.py")
#: Stay Python: package markers, the ``python -m tokenis`` entry and the glue that gives
#: third-party frameworks plain functions (they reject compiled ones; see tokenis/_glue.py).
KEEP_AS_PYTHON = ("__init__.py", "__main__.py", "_glue.py")
LICENSE_EXPRESSION = "LicenseRef-Tokenis-Proprietary"
SOURCE_URL = re.compile(r"https://github\.com/tokenismcp/tokenis-mcp")
DISTRIBUTION_URL = os.environ.get("TOKENIS_DISTRIBUTION_URL", "https://github.com/tokenismcp/tokenis")
DEBUG = os.environ.get("CLOSED_BUILD_DEBUG") == "1"


def _run(cmd: List[str], *, cwd: Optional[Path] = None, what: str) -> None:
    result = subprocess.run(cmd, cwd=cwd, check=False, capture_output=not DEBUG, text=True)
    if result.returncode:
        raise RuntimeError(f"{what} failed (exit {result.returncode}); set CLOSED_BUILD_DEBUG=1 to see why")


_COMPILE = r'''
import sys
from pathlib import Path
from Cython.Build import cythonize
from setuptools import Extension, setup

stage, work = Path(sys.argv[1]), Path(sys.argv[2])
modules = [l.split("\t") for l in Path(sys.argv[3]).read_text().splitlines()]
extensions = [Extension(name, [path]) for name, path in modules]
ext_modules = cythonize(
    extensions, quiet=True, build_dir=str(work / "cython"),
    compiler_directives={"language_level": "3", "binding": True, "emit_code_comments": False,
                         "annotation_typing": False, "c_string_type": "str", "c_string_encoding": "utf-8"},
)
setup(name="tokenis-compiled", ext_modules=ext_modules, package_dir={"": str(stage)}, script_args=[
    "build_ext", "--build-lib", str(work / "lib"), "--build-temp", str(work / "tmp"), "-q"])
'''


def _maturin_wheel(out: Path) -> Path:
    _run([sys.executable, "-m", "maturin", "build", "--release", "--out", str(out)], cwd=ROOT, what="maturin build")
    wheels = sorted(out.glob("tokenis_mcp-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one maturin wheel, found {[w.name for w in wheels]}")
    return wheels[0]


def _compile_package(stage: Path, work: Path) -> int:
    modules = []
    for path in sorted((stage / "tokenis").rglob("*.py")):
        rel = path.relative_to(stage).as_posix()
        if EXCLUDE.search(rel) or any(rel.startswith(d) for d in DROP_DIRS):
            path.unlink()
            continue
        if path.name in KEEP_AS_PYTHON:
            continue
        modules.append((rel[:-3].replace("/", "."), path))
    listing = work / "modules.tsv"
    listing.write_text("\n".join(f"{name}\t{path}" for name, path in modules), encoding="utf-8")
    script = work / "compile.py"
    script.write_text(_COMPILE, encoding="utf-8")
    _run([sys.executable, str(script), str(stage), str(work), str(listing)], what="compiling the modules")
    count = 0
    for item in sorted((work / "lib").rglob("*")):
        if item.is_file() and item.suffix in (".so", ".pyd"):
            target = stage / item.relative_to(work / "lib")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)
            count += 1
    for _, path in modules:
        path.unlink(missing_ok=True)
    for cache in (stage / "tokenis").rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)
    leftovers = [p.relative_to(stage).as_posix() for p in (stage / "tokenis").rglob("*.py")
                 if p.name not in KEEP_AS_PYTHON]
    if leftovers or count != len(modules):
        raise RuntimeError(f"compiled {count} of {len(modules)} modules; sources left: {leftovers[:5]}")
    return count


def _rewrite_metadata(stage: Path) -> Path:
    dist_info = next(stage.glob("tokenis_mcp-*.dist-info"))
    meta = dist_info / "METADATA"
    head, _, body = meta.read_text(encoding="utf-8").partition("\n\n")
    head = re.sub(r"^License-Expression:.*$", f"License-Expression: {LICENSE_EXPRESSION}", head, flags=re.MULTILINE)
    head = re.sub(r"^License-File:.*\n?", "", head, flags=re.MULTILINE)
    head = SOURCE_URL.sub(DISTRIBUTION_URL, head)
    head = re.sub(r"^Project-URL: (Repository|Issues|Changelog|Papers).*\n?", "", head, flags=re.MULTILINE)
    readme = os.environ.get("TOKENIS_PUBLIC_README")
    if readme and Path(readme).is_file():
        body = Path(readme).read_text(encoding="utf-8")
    else:
        body = SOURCE_URL.sub(DISTRIBUTION_URL, body)
    shutil.rmtree(dist_info / "licenses", ignore_errors=True)
    eula = Path(__file__).resolve().parent / "LICENSE-TOKENIS.txt"
    if eula.exists():
        (dist_info / "licenses").mkdir(exist_ok=True)
        shutil.copy2(eula, dist_info / "licenses" / "LICENSE-TOKENIS.txt")
        head += "\nLicense-File: LICENSE-TOKENIS.txt"
    meta.write_text(head + "\n\n" + body, encoding="utf-8")
    return dist_info


def _pack(stage: Path, dist_info: Path, out: Path, version: str) -> str:
    py = f"cp{sys.version_info.major}{sys.version_info.minor}"
    platform = re.sub(r"[-.]", "_", sysconfig.get_platform())
    name = f"tokenis_mcp-{version}-{py}-{py}-{platform}.whl"
    wheel_file = dist_info / "WHEEL"
    lines = [l for l in wheel_file.read_text(encoding="utf-8").splitlines() if not l.startswith("Tag:")]
    lines = [re.sub(r"^Root-Is-Purelib:.*", "Root-Is-Purelib: false", l) for l in lines]
    lines.append(f"Tag: {py}-{py}-{platform}")
    wheel_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rows = []
    with zipfile.ZipFile(out / name, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(stage.rglob("*")):
            if not path.is_file() or path.name == "RECORD":
                continue
            data = path.read_bytes()
            arc = path.relative_to(stage).as_posix()
            archive.writestr(arc, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            rows.append((arc, f"sha256={digest}", str(len(data))))
        record = f"{dist_info.name}/RECORD"
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerows(rows)
        writer.writerow((record, "", ""))
        archive.writestr(record, buffer.getvalue())
    return name


def build(out: Path) -> str:
    """Build one compiled wheel for this interpreter into ``out``; return its file name."""
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tokenis-closed-") as tmp:
        work = Path(tmp)
        source_wheel = _maturin_wheel(work / "maturin")
        version = source_wheel.name.split("-")[1]
        stage = work / "stage"
        with zipfile.ZipFile(source_wheel) as archive:
            archive.extractall(stage)
        count = _compile_package(stage, work)
        name = _pack(stage, _rewrite_metadata(stage), out, version)
    print(f"{name}: {count} compiled modules, no .py source")
    return name


# -- PEP 517 --------------------------------------------------------------------------


def get_requires_for_build_wheel(config_settings: Optional[Dict[str, Any]] = None) -> List[str]:
    return []


def build_wheel(wheel_directory: str, config_settings: Optional[Dict[str, Any]] = None,
                metadata_directory: Optional[str] = None) -> str:
    return build(Path(wheel_directory))


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=ROOT / "dist")
    build(parser.parse_args().out)


if __name__ == "__main__":
    main()
