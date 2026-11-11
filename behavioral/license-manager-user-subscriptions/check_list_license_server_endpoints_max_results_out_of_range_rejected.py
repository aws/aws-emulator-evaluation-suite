"""list-license-server-endpoints-max-results-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-license-server-endpoints-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["license-manager-user-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListLicenseServerEndpoints rejects MaxResults=101 with ValidationException and its exact message, and
    with MaxResults=100 returns a list of at most 100 endpoints."""
    lmus = ctx.client("license-manager-user-subscriptions")
    _ensure_slr(ctx)

    code, message = _error(lambda: lmus.list_license_server_endpoints(MaxResults=101))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "1 validation error detected: Value '101' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    ), f"unexpected message: {message!r}"

    # positive control: the boundary value itself is accepted and the call succeeds
    resp = lmus.list_license_server_endpoints(MaxResults=100)
    assert "LicenseServerEndpoints" in resp, f"response missing LicenseServerEndpoints: {resp!r}"
    endpoints = resp["LicenseServerEndpoints"]
    assert isinstance(endpoints, list), f"expected a list, got {type(endpoints)!r}"
    assert len(endpoints) <= 100, f"MaxResults=100 must cap the page at 100, got {len(endpoints)}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"].split(",")[0].strip(), exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _ensure_slr(ctx):
    """license-manager-user-subscriptions API calls require the
    AWSServiceRoleForAWSLicenseManagerUserSubscriptionsService service-linked role to
    exist in the account; without it every call is rejected with
    AccessDeniedException("Service Linked role is not present") before the service
    ever evaluates the request. Create it idempotently, then poll a cheap real call
    until the role has actually propagated -- IAM's eventual consistency means the
    license-manager-user-subscriptions API can still see the role as absent for a
    few seconds right after CreateServiceLinkedRole returns."""
    import time

    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="license-manager-user-subscriptions.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise

    lmus_probe = ctx.client("license-manager-user-subscriptions")
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            lmus_probe.list_instances(MaxResults=1)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException" and "Service Linked role" in str(exc):
                time.sleep(3.0)
                continue
            return


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
