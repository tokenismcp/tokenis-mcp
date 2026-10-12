# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Shims that hand plain Python functions to third-party frameworks.

Starlette and the MCP SDK (through pydantic) inspect the functions they are
given and accept only real Python functions, not the compiled functions that
the packaged builds of the other modules contain. Everything here is generic
glue with no logic of its own, so this module is shipped as Python.
"""
from __future__ import annotations

import inspect
from typing import Any, Callable, Dict, List, Tuple

from mcp.server.mcpserver import Context
from pydantic import BaseModel


def pyroute(server: Any, path: str, **kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """``@server.custom_route(path, ...)`` for an async ``handler(request)``."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        async def handler(request: Any) -> Any:
            return await fn(request)

        handler.__name__ = getattr(fn, "__name__", "handler")
        server.custom_route(path, **kwargs)(handler)
        return fn

    return decorator


def pyresource(fn: Callable[[], Any]) -> Callable[[], Any]:
    def resource() -> Any:
        return fn()

    resource.__name__ = getattr(fn, "__name__", "resource")
    return resource


def pyprompt(fn: Callable[[str], str]) -> Callable[[str], str]:
    def prompt(question: str = "") -> str:
        return fn(question)

    prompt.__name__ = getattr(fn, "__name__", "prompt")
    return prompt


def _plain(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(exclude_none=True)
    return value


def make_tool(name: str, params: List[Tuple[str, Any, Any]], run: Callable[..., Any]) -> Callable:
    """An MCP tool function with the given keyword-only parameters
    ``(name, annotation, default)``, which calls ``run(ctx, tool_name, arguments)``."""

    async def tool(**kwargs: Any) -> Dict[str, Any]:
        ctx = kwargs.pop("ctx")
        result: Dict[str, Any] = await run(ctx, name, {k: _plain(v) for k, v in kwargs.items()})
        return result

    parameters = [inspect.Parameter("ctx", inspect.Parameter.KEYWORD_ONLY, annotation=Context)]
    annotations: Dict[str, Any] = {"ctx": Context}
    for pname, annotation, default in params:
        parameters.append(
            inspect.Parameter(pname, inspect.Parameter.KEYWORD_ONLY, annotation=annotation, default=default)
        )
        annotations[pname] = annotation
    annotations["return"] = dict
    tool.__signature__ = inspect.Signature(parameters, return_annotation=dict)  # type: ignore[attr-defined]
    tool.__annotations__ = annotations
    tool.__name__ = name
    tool.__qualname__ = name
    return tool
