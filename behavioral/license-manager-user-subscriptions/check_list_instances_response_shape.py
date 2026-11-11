"""list-instances-response-shape."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-instances-response-shape"
GROUP = "control-plane"
SERVICES = ["license-manager-user-subscriptions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInstances returns a list of well-typed instance summaries, and an InstanceId filter for an instance
    that does not exist returns an empty list."""
    lmus = ctx.client("license-manager-user-subscriptions")
    _ensure_slr(ctx)

    resp = lmus.list_instances(MaxResults=10)
    assert "InstanceSummaries" in resp, f"ListInstances response missing InstanceSummaries: {resp!r}"
    summaries = resp["InstanceSummaries"]
    assert isinstance(summaries, list), f"InstanceSummaries should be a list, got {type(summaries)!r}"
    for summary in summaries:
        assert "InstanceId" in summary and isinstance(summary["InstanceId"], str), (
            f"InstanceSummary.InstanceId should be a str, got {summary.get('InstanceId')!r}"
        )
        assert "Products" in summary and isinstance(summary["Products"], list), (
            f"InstanceSummary.Products should be a list, got {summary.get('Products')!r}"
        )
        assert "Status" in summary and isinstance(summary["Status"], str), (
            f"InstanceSummary.Status should be a str, got {summary.get('Status')!r}"
        )
        for optional_field in ("LastStatusCheckDate", "StatusMessage", "OwnerAccountId"):
            if optional_field in summary:
                assert isinstance(summary[optional_field], str), (
                    f"InstanceSummary.{optional_field} should be a str, got {summary[optional_field]!r}"
                )
    if "NextToken" in resp:
        assert isinstance(resp["NextToken"], str), f"NextToken should be a str, got {resp['NextToken']!r}"

    # A filter naming a real InstanceId that cannot exist must be honored (empty,
    # well-typed result), not ignored in favor of an unfiltered scan -- this holds
    # regardless of how many real instances the account has, unlike an equality
    # assertion on the unfiltered list would.
    filtered = lmus.list_instances(
        MaxResults=10, Filters=[{"Attribute": "InstanceId", "Operation": "Equals", "Value": "i-0000000000nonexist"}]
    )
    assert "InstanceSummaries" in filtered, f"filtered ListInstances missing InstanceSummaries: {filtered!r}"
    filtered_summaries = filtered["InstanceSummaries"]
    assert isinstance(filtered_summaries, list), (
        f"filtered InstanceSummaries should be a list, got {type(filtered_summaries)!r}"
    )
    assert filtered_summaries == [], (
        f"filtering by a nonexistent InstanceId should match nothing, got {filtered_summaries!r}"
    )


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
