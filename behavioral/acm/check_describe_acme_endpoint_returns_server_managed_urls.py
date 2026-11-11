"""describe-acme-endpoint-returns-server-managed-urls."""
from __future__ import annotations

import datetime
import re
import time
import uuid
from typing import Any, Callable
from urllib.parse import urlsplit

from behavioral_harness import tags

_DIRECTORY_PATH_RE = re.compile(r"/[0-9a-fA-F-]+/directory")

CHECK = "describe-acme-endpoint-returns-server-managed-urls"
GROUP = "server-side"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAcmeEndpoint reports an AWS-assigned ACME directory URL that the caller never
    supplied, and that field is not exposed as an accepted input on Create/UpdateAcmeEndpoint."""
    acm = ctx.client("acm")

    created = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        IdempotencyToken=_token("create"),
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )
    endpoint_arn = created["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn))

    # On real AWS, an ACME endpoint reaches a terminal Status (ACTIVE/FAILED) within a couple of
    # minutes. Status can also flip to ACTIVE a beat before the rest of the endpoint object
    # (EndpointUrl) is fully populated, so a single poll waits for both "terminal status" and,
    # once ACTIVE, "fields populated" together rather than splitting the wait into two separate
    # bounded windows that can add up past the overall check budget. Note that DescribeAcmeEndpoint
    # does not echo back a CertificateAuthority field at all (only AcmeEndpointArn, EndpointUrl,
    # Status, AuthorizationBehavior, Contact, CreatedAt, UpdatedAt are returned), so the predicate
    # must not wait on that key ever appearing.
    def _terminal_and_populated(ep: dict) -> bool:
        status = ep.get("Status")
        if status == "FAILED":
            return True
        if status == "ACTIVE":
            return bool(ep.get("EndpointUrl"))
        return False

    endpoint = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"],
        _terminal_and_populated,
        timeout_s=240,
        interval_s=3,
    )
    assert endpoint["Status"] == "ACTIVE", (
        f"endpoint entered {endpoint['Status']}: {endpoint.get('FailureReason')}"
    )

    # We never passed a URL/domain in the create request; ACM assigned it and it must be a
    # well-formed ACME directory URL on the service's host for the region. The path segment
    # identifying the endpoint is a server-generated opaque identifier, distinct from (not derived
    # from) the endpoint's ARN suffix, so we only assert the labels/shape, not a literal match
    # with the ARN.
    url = endpoint["EndpointUrl"]
    assert isinstance(url, str) and url.startswith("https://"), f"unexpected EndpointUrl: {url!r}"
    assert "directory" in url, f"expected an RFC 8555 directory URL, got: {url!r}"
    _assert_directory_url(url, ctx.region)

    # Echoed inputs are unchanged; the ARN, status and URL are server-computed outputs.
    # Note: DescribeAcmeEndpoint does not echo back the CertificateAuthority the endpoint was
    # created with at all, so we don't assert on that field here.
    assert endpoint["AcmeEndpointArn"] == endpoint_arn
    assert endpoint["AuthorizationBehavior"] == "PRE_APPROVED"
    assert isinstance(endpoint["CreatedAt"], datetime.datetime), (
        f"expected CreatedAt to be a datetime, got {type(endpoint['CreatedAt'])!r}"
    )

    # EndpointUrl is not a member of Create/UpdateAcmeEndpointRequest in the service model at
    # all, so passing it never reaches AWS -- botocore raises ParamValidationError while building
    # the request, before any HTTP call is made. That is a structural fact about the request
    # shape (verifiable from the Smithy model), not something a real-AWS assertion could ever
    # falsify, so asserting on the client-side rejection here would score a pass against every
    # target regardless of correctness. Nothing to assert past the shape check above.


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


def _token(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex}"[:32]


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
