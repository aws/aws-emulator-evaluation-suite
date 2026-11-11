"""capacity-manager-metric-dimensions-track-monitored-tag-keys."""
from __future__ import annotations

import datetime as dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-manager-metric-dimensions-track-monitored-tag-keys"
GROUP = "telemetry"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:ec2-capacity-manager")
def run(ctx) -> None:
    """UpdateCapacityManagerMonitoredTagKeys activation and deactivation are reflected in the response and in
    GetCapacityManagerMonitoredTagKeys (ending suspended); GetCapacityManagerMetricDimensions rows, when data
    is available yet, name only the caller's account.
    """
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    was_enabled = _capacity_manager_enabled(ec2)
    try:
        ec2.enable_capacity_manager(OrganizationsAccess=False)
    except ClientError as exc:
        raise AssertionError(f"EnableCapacityManager rejected: {exc.response['Error']['Code']}")
    if not was_enabled:
        ctx.on_cleanup(lambda: ec2.disable_capacity_manager())

    tag_key = ctx.unique_name("sim2real-cm-tag-")

    def _find_tag_key():
        next_token = None
        while True:
            kwargs = {"NextToken": next_token} if next_token else {}
            resp = ec2.get_capacity_manager_monitored_tag_keys(**kwargs)
            for entry in resp["CapacityManagerTagKeys"]:
                if entry["TagKey"] == tag_key:
                    return entry
            next_token = resp.get("NextToken")
            if not next_token:
                return None

    assert _find_tag_key() is None

    activate_resp = ec2.update_capacity_manager_monitored_tag_keys(ActivateTagKeys=[tag_key])
    activated_entries = [e for e in activate_resp["CapacityManagerTagKeys"] if e["TagKey"] == tag_key]
    assert len(activated_entries) == 1
    assert activated_entries[0]["Status"] in ("activating", "activated")

    activated = _poll_until(_find_tag_key, lambda e: e is not None, timeout_s=60)
    assert activated["TagKey"] == tag_key

    now = dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0, microsecond=0)
    end_time = now - dt.timedelta(hours=1)
    start_time = end_time - dt.timedelta(hours=24)
    try:
        dims = ec2.get_capacity_manager_metric_dimensions(
            GroupBy=["account-id"],
            MetricNames=["unreserved-total-usage-hrs-vcpu"],
            StartTime=start_time,
            EndTime=end_time,
        )["MetricDimensionResults"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "CapacityManager.DataNotAvailable":
            # A just-activated Capacity Manager has ingested no data yet, so every time range
            # is refused with this code until usage accrues; only the scoping read is skipped.
            dims = None
        else:
            raise
    if dims is not None:
        for entry in dims:
            assert entry["AccountId"] == account_id

    deactivate_resp = ec2.update_capacity_manager_monitored_tag_keys(DeactivateTagKeys=[tag_key])
    deactivated_entries = [
        e for e in deactivate_resp["CapacityManagerTagKeys"] if e["TagKey"] == tag_key
    ]
    assert len(deactivated_entries) == 1
    assert deactivated_entries[0]["Status"] in ("deactivating", "suspended")

    final = _poll_until(
        _find_tag_key,
        lambda e: e is None or e["Status"] == "suspended",
        timeout_s=120,
    )
    if final is not None:
        assert final["Status"] == "suspended"


def _capacity_manager_enabled(ec2) -> bool:
    """Whether Capacity Manager is on here; a never-enabled account refuses the read."""
    try:
        return ec2.get_capacity_manager_attributes()["CapacityManagerStatus"] == "enabled"
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "CapacityManager.Disabled":
            raise
        return False


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
