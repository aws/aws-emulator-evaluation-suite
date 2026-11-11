"""list-instances-bogus-filter-attribute-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-instances-bogus-filter-attribute-rejected"
GROUP = "overly-permissive"
SERVICES = ["license-manager-user-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListInstances accepts an InstanceId filter and no filter, and rejects an unknown filter attribute with
    ValidationException "Invalid Filter attribute NotARealAttributeXYZ"."""
    lmus = ctx.client("license-manager-user-subscriptions")
    _ensure_slr(ctx)

    # Positive control: a *documented* filter attribute must still be accepted.
    # This is what actually discriminates "rejects the bogus attribute name" from
    # "rejects any Filters at all" -- a bare no-Filters call cannot tell those apart.
    resp_valid_filter = lmus.list_instances(
        Filters=[{"Attribute": "InstanceId", "Operation": "Equals", "Value": "i-00000000000000000"}]
    )
    assert "InstanceSummaries" in resp_valid_filter, f"missing InstanceSummaries: {resp_valid_filter!r}"
    assert isinstance(resp_valid_filter["InstanceSummaries"], list), (
        f"InstanceSummaries not a list: {resp_valid_filter['InstanceSummaries']!r}"
    )

    # "Equals" (proven valid above) isolates the Attribute name as the only thing
    # wrong with this filter -- real AWS rejects an unsupported Operation value
    # (e.g. "eq") on its own, independent of Attribute, so pairing the bogus
    # Attribute with an unproven Operation would not actually discriminate the two.
    code, message = _error(
        lambda: lmus.list_instances(
            Filters=[{"Attribute": "NotARealAttributeXYZ", "Operation": "Equals", "Value": "x"}]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Invalid Filter attribute NotARealAttributeXYZ", f"unexpected message: {message!r}"

    resp = lmus.list_instances()
    assert "InstanceSummaries" in resp, f"missing InstanceSummaries: {resp!r}"
    assert isinstance(resp["InstanceSummaries"], list), f"InstanceSummaries not a list: {resp['InstanceSummaries']!r}"


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
