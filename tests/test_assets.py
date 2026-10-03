# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The browser pages: their scripts parse, and every text has a Korean and
an English version."""
import json
import re
import shutil
import subprocess
from importlib import resources

import pytest

PAGES = ("admin.html", "ask.html")
NODE = shutil.which("node")


def page(name):
    return resources.files("tokenis").joinpath("assets/" + name).read_text(encoding="utf-8")


def script(name):
    return re.search(r'<script nonce="\{\{nonce\}\}">(.*?)</script>', page(name), re.DOTALL).group(1)


@pytest.mark.skipif(NODE is None, reason="needs node")
@pytest.mark.parametrize("name", PAGES)
def test_page_scripts_parse(tmp_path, name):
    path = tmp_path / (name + ".js")
    path.write_text(script(name), encoding="utf-8")
    result = subprocess.run([NODE, "--check", str(path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def dictionary(name, marker):
    """The translation table, evaluated by node (it is a JS object literal)."""
    src = script(name)
    start = src.index(marker) + len(marker)
    depth, i = 0, start
    while True:
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    literal = src[start:i + 1]
    out = subprocess.run([NODE, "-e", f"process.stdout.write(JSON.stringify(({literal})))"],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


@pytest.mark.skipif(NODE is None, reason="needs node")
@pytest.mark.parametrize("name,marker", [("admin.html", "const I18N = "), ("ask.html", "const T = ")])
def test_every_text_exists_in_both_languages(name, marker):
    table = dictionary(name, marker)
    assert set(table) == {"en", "ko"}
    assert set(table["en"]) == set(table["ko"])
    used = set(re.findall(r'\bt\("([a-z0-9_]+)"', script(name))) | set(
        re.findall(r'data-(?:i18n(?:-html)?|t(?:-html)?)="([a-z0-9_]+)"', page(name)))
    missing = {k for k in used - set(table["en"]) if not k.endswith("_")}  # "p_" + name: built at run time
    assert not missing, sorted(missing)
    placeholders = re.compile(r"\{(\w+)\}")
    for key, text in table["en"].items():
        if isinstance(text, str):
            assert set(placeholders.findall(text)) == set(placeholders.findall(table["ko"][key])), key


def test_pages_take_the_language_and_nonce_from_the_server():
    for name in PAGES:
        html = page(name)
        assert '<html lang="{{lang}}">' in html
        assert "{{nonce}}" in html and "style=" not in html.split("<script")[0].split("</style>")[1]
