"""A test's client sends each request where the customer's SDK sends it, and one aimed at a host
the emulator does not serve fails the test before it is sent; a tool gets no S3 Control endpoint;
``endpoint_url`` dials a published RTMP(S) ingest address."""

from urllib.parse import urlsplit

import pytest

from fidelity_tests_runner import run as run_module
from fidelity_tests_runner.context import FIXED_CREDS, CapabilityNotOffered, Context
from fidelity_tests_runner.harness import VERDICT_FAILED
from fidelity_tests_runner.published import PublishedUrlRejected
from fidelity_tests_runner.target import EndpointRefused, assert_tls_verification_permitted

ENDPOINT = "http://127.0.0.1:9"
ACCOUNT = "000000000000"


class _Captured(Exception):
    """Raised by the fake sender in place of sending a request."""


def _sender(client) -> list[str]:
    """The URLs ``client`` reaches its sender with: each raises ``_Captured`` instead of sending."""
    sent: list[str] = []

    def capture(request, **_):
        sent.append(request.url)
        raise _Captured(request.url)

    client.meta.events.register_last("before-send", capture)
    return sent


def test_a_request_to_the_endpoint_host_is_sent():
    client = Context(ENDPOINT, creds=FIXED_CREDS).client("sqs")
    sent = _sender(client)
    with pytest.raises(_Captured):
        client.list_queues()
    assert len(sent) == 1 and sent[0].startswith(f"{ENDPOINT}/")


def test_a_request_a_ruleset_aims_off_the_endpoint_fails_the_test_unsent():
    client = Context(ENDPOINT, creds=FIXED_CREDS).client("signin")
    sent = _sender(client)
    with pytest.raises(CapabilityNotOffered, match="the emulator serves no address for") as info:
        client.get_console_authorization_configuration()
    host = str(info.value).rpartition(" ")[2]
    assert host.endswith((".aws", ".amazonaws.com")), host
    assert sent == []


def test_a_name_under_an_ip_literal_fails_the_test_unsent():
    client = Context(ENDPOINT, creds=FIXED_CREDS).client("s3control")
    sent = _sender(client)
    with pytest.raises(CapabilityNotOffered, match=rf"no address for {ACCOUNT}\.127\.0\.0\.1$"):
        client.list_access_points(AccountId=ACCOUNT)
    assert sent == []


def test_a_request_to_a_documented_own_host_is_sent():
    ctx = Context(ENDPOINT, creds=FIXED_CREDS, own_hosts=["*.emu.test"])
    client = ctx.client("sqs", endpoint_url="http://sqs.emu.test:9")
    sent = _sender(client)
    with pytest.raises(_Captured):
        client.list_queues()
    assert [urlsplit(url).netloc for url in sent] == ["sqs.emu.test:9"]


def test_a_refused_request_fails_the_test_as_scored():
    def check(ctx):
        ctx.client("signin").get_console_authorization_configuration()

    result = run_module.run_check(
        lambda: Context(ENDPOINT, creds=FIXED_CREDS), "c", "g", check, timeout_s=30
    )
    assert result.verdict == VERDICT_FAILED and not result.runner_fault
    assert "the emulator serves no address for" in result.detail


def test_a_tool_gets_no_s3_control_endpoint(monkeypatch):
    monkeypatch.setenv("AWS_ENDPOINT_URL_S3_CONTROL", "https://elsewhere.example:9")
    ctx = Context(ENDPOINT, creds=FIXED_CREDS)
    try:
        env = ctx.subprocess_env()
        assert "AWS_ENDPOINT_URL_S3_CONTROL" not in env
        assert env["AWS_ENDPOINT_URL"] == ENDPOINT
    finally:
        ctx.run_cleanups()


@pytest.mark.parametrize(
    ("endpoint", "published", "url"),
    [
        ("http://127.0.0.1:4566", "127.0.0.1:4935", "rtmps://127.0.0.1:4935"),
        ("http://localhost:4566", "localhost:4566", "rtmps://localhost:4566"),
    ],
)
def test_endpoint_url_gives_a_bare_host_the_scheme_the_test_names(endpoint, published, url):
    ctx = Context(endpoint, creds=FIXED_CREDS)
    assert ctx.endpoint_url(published, scheme="rtmps", aws_port=443) == url


@pytest.mark.parametrize(
    "published",
    ["rtmp://127.0.0.1:1935/app/", "rtmps://127.0.0.1:4566/app/key", "RTMPS://127.0.0.1/app/"],
)
def test_endpoint_url_uses_a_published_rtmp_url_on_an_own_host(published):
    ctx = Context("http://localhost:4566", creds=FIXED_CREDS, verify_ssl=False)
    assert ctx.endpoint_url(published) == published
    assert ctx.endpoint_url(published, websocket=True) == published


def test_endpoint_url_rejects_an_aws_ingest_host():
    ctx = Context("http://localhost:4566", creds=FIXED_CREDS)
    with pytest.raises(PublishedUrlRejected, match="needs rtmps://localhost:4566/"):
        ctx.endpoint_url("rtmps://abc.global-contribute.live-video.net:443/app/")
    with pytest.raises(PublishedUrlRejected):
        ctx.endpoint_url("abc.global-contribute.live-video.net", scheme="rtmps")


@pytest.mark.parametrize("scheme", ["ftp", "RTMPS", ""])
def test_endpoint_url_refuses_a_scheme_it_never_dials(scheme):
    ctx = Context(ENDPOINT, creds=FIXED_CREDS)
    with pytest.raises(ValueError, match="scheme is not one of"):
        ctx.endpoint_url("127.0.0.1", scheme=scheme)


@pytest.mark.parametrize("endpoint", ["rtmp://10.0.0.5:1935/app/", "ws://10.0.0.5:4510"])
def test_plain_rtmp_and_ws_carry_no_certificate_to_verify(endpoint):
    assert_tls_verification_permitted(endpoint, False)


@pytest.mark.parametrize("endpoint", ["rtmps://10.0.0.5:443/app/", "wss://10.0.0.5:4510"])
def test_unverified_tls_to_a_private_address_is_refused(endpoint):
    with pytest.raises(EndpointRefused, match="loopback"):
        assert_tls_verification_permitted(endpoint, False)
