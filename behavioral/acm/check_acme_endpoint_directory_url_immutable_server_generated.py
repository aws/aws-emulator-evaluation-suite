"""acme-endpoint-directory-url-immutable-server-generated."""
from __future__ import annotations

import re
import time
from urllib.parse import urlsplit

from behavioral_harness import tags

CHECK = "acme-endpoint-directory-url-immutable-server-generated"
GROUP = "server-side"
SERVICES = ["acm"]

_DIRECTORY_PATH_RE = re.compile(r"/[0-9a-fA-F-]+/directory")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The service assigns the ACME directory URL (the create request has no URL field); it
    stays identical across Describes, and a second endpoint with identical input gets a
    distinct URL, so it is server-generated rather than derived from client input."""
    acm = ctx.client("acm")

    arn1, url1 = _create_active_acme_endpoint(ctx, acm)
    reread_urls = []
    for _ in range(3):
        described = acm.describe_acme_endpoint(AcmeEndpointArn=arn1)["AcmeEndpoint"]
        reread_urls.append(described["EndpointUrl"])
        time.sleep(1)
    assert len(set(reread_urls)) == 1, f"EndpointUrl changed across repeated describes: {reread_urls}"
    assert reread_urls[0] == url1, f"expected {url1!r}, got {reread_urls[0]!r}"
    _assert_directory_url(url1, ctx.region)

    # Same AuthorizationBehavior/CertificateAuthority/Contact as endpoint 1 -- if the URL (or the
    # endpoint's identity) were derived from client input rather than server-generated, these
    # would collide with endpoint 1's despite the fresh CreateAcmeEndpoint call.
    arn2, url2 = _create_active_acme_endpoint(ctx, acm)
    assert arn2 != arn1, "two independently created endpoints with identical input got the same ARN"
    assert url2 != url1, "two independently created endpoints with identical input got the same directory URL"


def _assert_directory_url(url, region):
    """An ACME directory URL is ``https://acm-acme-enroll.<region>.<domain>/<id>/directory``. The
    domain is the target's own, so the service label and region are matched by position and the
    rest only has to be a domain."""
    parts = urlsplit(url)
    labels = (parts.hostname or "").split(".")
    assert parts.scheme == "https", f"EndpointUrl {url!r} is not an https URL"
    assert labels[:2] == ["acm-acme-enroll", region] and len(labels) > 2 and all(labels[2:]), (
        f"EndpointUrl {url!r} must be on acm-acme-enroll.{region}.<domain>")
    assert _DIRECTORY_PATH_RE.fullmatch(parts.path) and not parts.query and not parts.fragment, (
        f"EndpointUrl {url!r} must have the path /<id>/directory and nothing after it")


def _create_active_acme_endpoint(ctx, acm, timeout_s: float = 180.0, interval_s: float = 5.0):
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-endpoint-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))

    deadline = time.monotonic() + timeout_s
    endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    while endpoint["Status"] == "CREATING" and time.monotonic() < deadline:
        time.sleep(interval_s)
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    if endpoint["Status"] != "ACTIVE":
        raise AssertionError(
            f"ACME endpoint never reached ACTIVE (status={endpoint['Status']}, "
            f"reason={endpoint.get('FailureReason')})"
        )
    return arn, endpoint["EndpointUrl"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
