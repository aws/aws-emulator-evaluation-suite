"""acme-endpoint-server-managed-directory-url."""
from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlsplit

from behavioral_harness import tags

CHECK = "acme-endpoint-server-managed-directory-url"
GROUP = "server-side"
SERVICES = ["acm"]

_DIRECTORY_PATH_RE = re.compile(r"/[0-9a-fA-F-]{20,}/directory")
_ENDPOINT_ARN_RE = re.compile(
    r"^arn:aws[a-z-]*:acm:[a-z0-9-]+:[0-9]{12}:acme-endpoint/[a-zA-Z0-9-]+$"
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAcmeEndpoint assigns EndpointUrl and AcmeEndpointArn server-side: two endpoints created
    with identical input get distinct URLs and ARNs, so neither derives from the request."""
    identical_params: dict[str, Any] = {
        "AuthorizationBehavior": "PRE_APPROVED",
        "Contact": "NOT_REQUIRED",
        "CertificateAuthority": {"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
    }

    arn_a = _create_acme_endpoint(ctx, identical_params, "a")
    arn_b = _create_acme_endpoint(ctx, identical_params, "b")

    desc_a = _wait_for_endpoint_active(ctx, arn_a)
    desc_b = _wait_for_endpoint_active(ctx, arn_b)

    # Both endpoints echo the identical requested config...
    assert desc_a["AuthorizationBehavior"] == desc_b["AuthorizationBehavior"] == "PRE_APPROVED", (
        f"expected both endpoints to echo AuthorizationBehavior=PRE_APPROVED, "
        f"got a={desc_a['AuthorizationBehavior']!r} b={desc_b['AuthorizationBehavior']!r}"
    )
    assert desc_a["Contact"] == desc_b["Contact"] == "NOT_REQUIRED", (
        f"expected both endpoints to echo Contact=NOT_REQUIRED, "
        f"got a={desc_a['Contact']!r} b={desc_b['Contact']!r}"
    )

    # ...yet the server-assigned identity/URL differ despite identical input.
    assert arn_a != arn_b, f"expected distinct server-assigned ARNs, both were {arn_a!r}"
    assert desc_a["EndpointUrl"] != desc_b["EndpointUrl"], (
        f"expected distinct server-assigned EndpointUrls, both were {desc_a['EndpointUrl']!r}"
    )
    assert desc_a["AcmeEndpointArn"] == arn_a, (
        f"expected DescribeAcmeEndpoint to echo the ARN returned by CreateAcmeEndpoint, "
        f"got {desc_a['AcmeEndpointArn']!r} != {arn_a!r}"
    )
    assert desc_b["AcmeEndpointArn"] == arn_b, (
        f"expected DescribeAcmeEndpoint to echo the ARN returned by CreateAcmeEndpoint, "
        f"got {desc_b['AcmeEndpointArn']!r} != {arn_b!r}"
    )

    for arn, desc in ((arn_a, desc_a), (arn_b, desc_b)):
        assert _ENDPOINT_ARN_RE.match(arn), f"unexpected endpoint arn shape: {arn}"
        _assert_directory_url(desc["EndpointUrl"], ctx.region)

    # Re-describing returns the exact same server-assigned URL (stable identity, not
    # regenerated per read).
    acm = ctx.client("acm")
    redescribed = acm.describe_acme_endpoint(AcmeEndpointArn=arn_a)["AcmeEndpoint"]
    assert redescribed["EndpointUrl"] == desc_a["EndpointUrl"], (
        f"expected a re-describe to return the same EndpointUrl, "
        f"got {redescribed['EndpointUrl']!r} != {desc_a['EndpointUrl']!r}"
    )


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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_acme_endpoint(ctx, params: dict, suffix: str) -> str:
    acm = ctx.client("acm")
    request = dict(params)
    request["Tags"] = [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-acm-endpoint-{suffix}-")}]
    arn = acm.create_acme_endpoint(**request)["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    return arn


def _wait_for_endpoint_active(ctx, endpoint_arn, timeout_s=180.0, interval_s=5.0):
    acm = ctx.client("acm")

    def probe():
        return acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]

    def done(desc):
        if desc["Status"] == "FAILED":
            raise AssertionError(f"AcmeEndpoint {endpoint_arn} FAILED: {desc.get('FailureReason')}")
        return desc["Status"] == "ACTIVE"

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
