"""capacity-manager-organizations-access-toggle-scopes-metric-data."""
from __future__ import annotations

import datetime as dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-manager-organizations-access-toggle-scopes-metric-data"
GROUP = "telemetry"
SERVICES = ["ec2"]


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:metrics",
    "concern:negative-classes",
    "concern:representation",
    "plane:control", "resource:account-singleton:ec2-capacity-manager",
)
def run(ctx) -> None:
    """With Capacity Manager enabled on an account without Organizations trusted access, enabling Organizations
    access is refused with CapacityManager.OrganizationTrustedAccessDisabled and its exact message and the flag
    stays False; metric data is DataNotAvailable with its exact message or names only the caller's account.
    """
    ec2 = ctx.client("ec2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    was_enabled = _capacity_manager_enabled(ec2)
    try:
        ec2.enable_capacity_manager(OrganizationsAccess=False)
    except ClientError as exc:
        raise AssertionError(f"EnableCapacityManager rejected: {exc.response['Error']['Code']}")
    if not was_enabled:
        ctx.on_cleanup(lambda: ec2.disable_capacity_manager())

    baseline = ec2.get_capacity_manager_attributes()
    assert baseline["OrganizationsAccess"] is False, baseline

    try:
        ec2.update_capacity_manager_organizations_access(OrganizationsAccess=True)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "CapacityManager.OrganizationTrustedAccessDisabled", (
            "expected CapacityManager.OrganizationTrustedAccessDisabled, got "
            f"{code!r}: {exc.response['Error']}"
        )
        assert exc.response["Error"]["Message"] == (
            "This account can't access Capacity Manager with AWS Organizations. "
            "Enable trusted access or use account mode."), exc.response["Error"]
    else:
        raise AssertionError(
            "UpdateCapacityManagerOrganizationsAccess(OrganizationsAccess=True) "
            "unexpectedly succeeded on an account that is not an AWS Organizations "
            "management/delegated-administrator account"
        )

    # Effect-absent: the refused toggle must not have flipped the flag.
    after = ec2.get_capacity_manager_attributes()["OrganizationsAccess"]
    assert after is False, f"expected OrganizationsAccess to stay False after the refusal, got {after!r}"

    # StartTime/EndTime must be truncated to the hour, or the real API rejects the
    # call with InvalidParameterValue ("StartTime must be truncated to the hour").
    end = dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = end - dt.timedelta(hours=24)
    try:
        dims = ec2.get_capacity_manager_metric_data(
            MetricNames=["unreserved-total-usage-hrs-vcpu"],
            GroupBy=["account-id"],
            StartTime=start,
            EndTime=end,
            Period=3600,
        )["MetricDataResults"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        # Capacity Manager was just enabled moments ago in this run, so it has not
        # ingested any usage data yet -- this is the deterministic, immediate
        # response, not a transient error worth retrying.
        assert code == "CapacityManager.DataNotAvailable", (
            f"expected CapacityManager.DataNotAvailable, got {code!r}: {exc.response['Error']}"
        )
        assert exc.response["Error"]["Message"] == (
            "Capacity Manager data isn't available yet. Try again later."), exc.response["Error"]
    else:
        for row in dims:
            dimension = row.get("Dimension") or {}
            # Every row must be scoped to exactly the caller's own account -- never a
            # placeholder, and never some other id -- as Organizations access
            # could not be granted above.
            assert dimension.get("AccountId") == account_id, (
                f"expected every row scoped to caller account {account_id!r}, got {dimension!r}"
            )


def _capacity_manager_enabled(ec2) -> bool:
    """Whether Capacity Manager is on here; a never-enabled account refuses the read."""
    try:
        return ec2.get_capacity_manager_attributes()["CapacityManagerStatus"] == "enabled"
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "CapacityManager.Disabled":
            raise
        return False

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
