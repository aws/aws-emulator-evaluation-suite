"""Tests make no Python-level socket connection off this machine: a ``connect`` or ``connect_ex``
to any other host fails the test that made it. A test hygiene check: a
subprocess or a C extension that opens its own sockets is not covered."""

import ipaddress
import socket

import pytest

_connect = socket.socket.connect
_connect_ex = socket.socket.connect_ex


def _refuse_off_loopback(address) -> None:
    host = address[0] if isinstance(address, tuple) else address
    try:
        allowed = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        allowed = False
    if not allowed:
        raise OSError(f"tests are offline; refused a connection to {address!r}")


def _loopback_only(self, address):
    _refuse_off_loopback(address)
    return _connect(self, address)


def _loopback_only_ex(self, address):
    _refuse_off_loopback(address)
    return _connect_ex(self, address)


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", _loopback_only)
    monkeypatch.setattr(socket.socket, "connect_ex", _loopback_only_ex)
