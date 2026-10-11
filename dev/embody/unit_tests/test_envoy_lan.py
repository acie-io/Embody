"""The acie-io fork's LAN listener: which Host headers Envoy admits.

Envoy binds every interface in this fork, and the MCP SDK's Host check
admits only the names in `allowed_hosts`. `_lan_hosts` supplies this
machine's names and addresses; a name it misses is a client on the LAN
refused with 421.
"""

from __future__ import annotations

import importlib.util
import socket
from pathlib import Path

import pytest

_EMBODY = Path(__file__).resolve().parents[1] / "Embody"


def _load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, _EMBODY / relpath)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_ENVOY = _load("lan_envoy", "EnvoyExt.py")


def test_lan_hosts_names_this_machine_in_lowercase(monkeypatch):
    monkeypatch.setattr(socket, "gethostname", lambda: "LIGHT")
    monkeypatch.setattr(
        socket,
        "gethostbyname_ex",
        lambda name: (name, [], ["10.10.11.13", "192.168.1.5"]),
    )

    assert _ENVOY._lan_hosts() == [
        "10.10.11.13:*",
        "192.168.1.5:*",
        "light:*",
        "light.local:*",
    ]


def test_lan_hosts_keeps_the_names_when_the_lookup_fails(monkeypatch):
    def refuse(name):
        raise socket.gaierror("no address")

    monkeypatch.setattr(socket, "gethostname", lambda: "light")
    monkeypatch.setattr(socket, "gethostbyname_ex", refuse)

    assert _ENVOY._lan_hosts() == ["light:*", "light.local:*"]


def test_lan_hosts_pass_the_sdk_host_check(monkeypatch):
    transport_security = pytest.importorskip("mcp.server.transport_security")
    monkeypatch.setattr(socket, "gethostname", lambda: "light")
    monkeypatch.setattr(
        socket,
        "gethostbyname_ex",
        lambda name: (name, [], ["10.10.11.13"]),
    )
    settings = transport_security.TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["127.0.0.1:*", *_ENVOY._lan_hosts()],
    )
    check = transport_security.TransportSecurityMiddleware(settings)

    assert check._validate_host("light.local:9870")
    assert check._validate_host("10.10.11.13:9870")
    assert not check._validate_host("evil.example:9870")
