"""While a test runs, a host it dials itself is refused before it is resolved unless the emulator
serves it; the guard is idle outside a run."""

import socket
import urllib.request

import pytest

from fidelity_tests_runner import egress
from fidelity_tests_runner import run as run_module
from fidelity_tests_runner.context import FIXED_CREDS, CapabilityNotOffered, Context
from fidelity_tests_runner.harness import VERDICT_FAILED

ENDPOINT = "http://127.0.0.1:9"
AWS_URL = "https://example.auth.us-east-1.amazoncognito.com/oauth2/token"


def test_a_url_a_test_dials_itself_is_refused_before_it_is_resolved(monkeypatch):
    looked_up: list[str] = []
    real = socket.getaddrinfo

    def spy(host, *args, **kwargs):
        looked_up.append(host)
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", spy)
    with egress.guarding(ENDPOINT), pytest.raises(CapabilityNotOffered, match="amazoncognito"):
        urllib.request.urlopen(AWS_URL, timeout=5)
    assert looked_up == ["example.auth.us-east-1.amazoncognito.com"]  # refused at this lookup


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "api.localhost", "10.0.0.5"])
def test_a_local_host_is_resolved(host):
    with egress.guarding(ENDPOINT):
        socket.getaddrinfo(host, 80)


def test_a_documented_own_host_is_permitted_and_another_name_is_not():
    assert egress.permits("bkt.emu.test", ENDPOINT, ["*.emu.test"])
    assert not egress.permits("bkt.emu.test", ENDPOINT)
    assert not egress.permits("s3.us-east-1.amazonaws.com", ENDPOINT, ["*.emu.test"])


def test_a_name_under_an_ip_literal_is_refused():
    with egress.guarding(ENDPOINT), pytest.raises(CapabilityNotOffered):
        socket.getaddrinfo("000000000000.127.0.0.1", 443)


@pytest.mark.parametrize("lookup", [socket.gethostbyname, socket.gethostbyname_ex])
def test_every_resolver_is_guarded(lookup):
    with egress.guarding(ENDPOINT), pytest.raises(CapabilityNotOffered):
        lookup("aws.amazon.com")


def test_the_guard_is_idle_outside_a_run():
    with egress.guarding(ENDPOINT):
        pass
    with pytest.raises(socket.gaierror):  # resolved, not refused
        socket.getaddrinfo("000000000000.127.0.0.1", 443)


def test_a_test_that_dials_an_aws_host_itself_fails_as_scored():
    def check(ctx):
        urllib.request.urlopen(AWS_URL, timeout=5)

    result = run_module.run_check(
        lambda: Context(ENDPOINT, creds=FIXED_CREDS), "c", "g", check, timeout_s=30
    )
    assert result.verdict == VERDICT_FAILED and not result.runner_fault
    assert "the emulator serves no address for example.auth" in result.detail
