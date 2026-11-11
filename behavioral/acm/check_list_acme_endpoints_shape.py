"""list-acme-endpoints-shape."""
from __future__ import annotations

import time
from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-acme-endpoints-shape"
GROUP = 'error-semantics'
SERVICES = ['acm']

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)

def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on ACM throttle codes (test-infra robustness, not a behavioral assertion)."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (i + 1))
    raise last

def _ignore_not_found(fn, timeout_s=120.0):
    """Teardown delete: return once it succeeds or the endpoint is already gone; retry the
    documented ConflictException while the endpoint is still settling; raise the rest."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


def _find_in_list(acm, arn, timeout_s=60.0, interval_s=2.0):
    """Page through ListAcmeEndpoints until `arn` appears, returning the full page it
    appeared on. A just-created endpoint is not guaranteed to be visible on the first
    call, so this is a bounded retry, not a single read."""
    deadline = time.monotonic() + timeout_s
    page_items: list[dict] = []
    while time.monotonic() < deadline:
        page_items = []
        next_token = None
        while True:
            kwargs = {"MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token
            page = _retry_throttle(lambda: acm.list_acme_endpoints(**kwargs))
            page_items.extend(page.get("AcmeEndpoints", []))
            next_token = page.get("NextToken")
            if not next_token:
                break
        if any(ep.get("AcmeEndpointArn") == arn for ep in page_items):
            return page_items
        time.sleep(interval_s)
    raise AssertionError(f"created endpoint {arn} did not appear in ListAcmeEndpoints within {timeout_s}s")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAcmeEndpoints returns a well-formed AcmeEndpoints collection that includes a
    just-created endpoint."""
    acm = ctx.client("acm")
    if not hasattr(acm, "list_acme_endpoints") or not hasattr(acm, "create_acme_endpoint"):
        raise AssertionError("Acme endpoint operations not present in the installed botocore model")

    arn = _retry_throttle(lambda: acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))

    # A shape check against an always-empty collection is vacuous -- ensure there is at
    # least one real endpoint before asserting the collection's per-item shape.
    endpoints = _find_in_list(acm, arn)
    assert isinstance(endpoints, list), type(endpoints)
    assert endpoints, "ListAcmeEndpoints returned no entries despite a just-created endpoint"
    for ep in endpoints:
        assert "AcmeEndpointArn" in ep, ep


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
