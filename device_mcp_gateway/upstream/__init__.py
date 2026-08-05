# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Talking to a remote MCP server as an upstream (ADR-0009).

The gateway's original upstream was an OpenAPI-documented API it translated. These modules
add the second kind: an MCP server it proxies. They own the wire protocol and discovery;
serving the result to clients stays in ``pods/``.
"""
