"""acme-endpoint-directory-url-managed-by-service."""
from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlsplit

from behavioral_harness import tags

CHECK = "acme-endpoint-directory-url-managed-by-service"
GROUP = "server-side"
SERVICES = ["acm"]

_DIRECTORY_PATH_RE = re.compile(r"/[0-9a-fA-F-]+/directory")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """The service-computed EndpointUrl is well-formed, stable across Describes and an unrelated
    UpdateAcmeEndpoint, and distinct for a second endpoint created with identical input."""
    acm = ctx.client("acm")
    endpoint_arn = _create_endpoint(ctx, contact="NOT_REQUIRED", suffix="a")
    endpoint = _wait_for_endpoint_active(ctx, endpoint_arn)

    url_1 = endpoint["EndpointUrl"]
    assert url_1, "EndpointUrl must be populated once the endpoint is ACTIVE"
    _assert_directory_url(url_1, ctx.region)

    url_2 = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]["EndpointUrl"]
    assert url_2 == url_1, "EndpointUrl changed across repeated DescribeAcmeEndpoint calls"

    # Mutate an unrelated attribute; the directory URL must be untouched by it.
    acm.update_acme_endpoint(AcmeEndpointArn=endpoint_arn, Contact="REQUIRED")
    url_3 = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]["EndpointUrl"]
    assert url_3 == url_1, "EndpointUrl changed after an unrelated UpdateAcmeEndpoint call"

    # A second endpoint created with byte-for-byte identical input must get an
    # independently minted URL -- this rules out a target that answers with a
    # fixed or request-derived constant instead of a real per-endpoint value.
    endpoint_arn_2 = _create_endpoint(ctx, contact="NOT_REQUIRED", suffix="b")
    endpoint_2 = _wait_for_endpoint_active(ctx, endpoint_arn_2)
    url_4 = endpoint_2["EndpointUrl"]
    _assert_directory_url(url_4, ctx.region)
    assert url_4 != url_1, "two endpoints created with identical input got the same directory URL"


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


def _create_endpoint(ctx: Any, contact: str = "NOT_REQUIRED", suffix: str = "a") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
        Tags=[{"Key": "Name", "Value": ctx.unique_name(f"sim2real-acm-endpoint-{suffix}-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    return arn


def _wait_for_endpoint_active(ctx: Any, arn: str, timeout_s: float = 180.0) -> dict:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        status = endpoint["Status"]
        if status == "ACTIVE":
            return endpoint
        if status == "FAILED":
            raise AssertionError(f"ACME endpoint {arn} failed: {endpoint.get('FailureReason')}")
        time.sleep(3)
    raise AssertionError(f"ACME endpoint {arn} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
