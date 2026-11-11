"""op-contract-get-capacity-manager-metric-data-dup."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-capacity-manager-metric-data-dup"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DATA_NOT_AVAILABLE_MESSAGE = "Capacity Manager data isn't available yet. Try again later."


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:ec2-capacity-manager")
def run(ctx) -> None:
    """GetCapacityManagerMetricData with DryRun fails with DryRunOperation and the standard message;
    without DryRun it fails with CapacityManager.DataNotAvailable and its exact message while the
    account reports no datapoint, and returns a list of MetricDataResults once one exists."""
    ec2 = ctx.client("ec2")
    _ensure_capacity_manager_enabled(ec2, ctx)

    end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=1)
    kwargs = dict(
        StartTime=start,
        EndTime=end,
        Period=3600,
        MetricNames=["reservation-total-count"],
        GroupBy=["instance-family"],
    )

    # DryRun's permission check is evaluated ahead of the data-availability check.
    code, message = _error(lambda: ec2.get_capacity_manager_metric_data(DryRun=True, **kwargs))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message {message!r}"
    )

    # Account-wide data availability is account state, not something this check owns, so the
    # independent read (GetCapacityManagerAttributes) decides which contract applies.
    attrs = ec2.get_capacity_manager_attributes()
    if attrs.get("LatestDatapointTimestamp") is None:
        code, message = _error(lambda: ec2.get_capacity_manager_metric_data(**kwargs))
        assert code == "CapacityManager.DataNotAvailable", (
            f"expected CapacityManager.DataNotAvailable with no datapoint reported, got {code!r}"
        )
        assert message == _DATA_NOT_AVAILABLE_MESSAGE, (
            f"unexpected CapacityManager.DataNotAvailable message {message!r}"
        )
    else:
        # Query the last hour the account reports data for: a window outside the available
        # range is refused with InvalidParameterValue.
        latest = attrs["LatestDatapointTimestamp"].astimezone(timezone.utc)
        latest = latest.replace(minute=0, second=0, microsecond=0)
        window = dict(kwargs, StartTime=latest - timedelta(hours=1), EndTime=latest)
        resp = ec2.get_capacity_manager_metric_data(**window)
        assert isinstance(resp["MetricDataResults"], list), (
            f"expected a list-shaped MetricDataResults, got {resp.get('MetricDataResults')!r}"
        )


def _ensure_capacity_manager_enabled(ec2, ctx) -> None:
    try:
        attrs = ec2.get_capacity_manager_attributes()
        enabled = attrs["CapacityManagerStatus"] == "enabled"
    except ClientError as exc:
        if _code(exc) != "CapacityManager.Disabled":
            raise
        enabled = False

    if enabled:
        return

    _enable_capacity_manager(ec2)
    ctx.on_cleanup(lambda: _safe(lambda: ec2.disable_capacity_manager()))
    _poll_until(
        lambda: ec2.get_capacity_manager_attributes(),
        lambda a: a["CapacityManagerStatus"] == "enabled",
        timeout_s=120,
    )


def _safe(fn) -> None:
    fn()


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _code(exc: ClientError) -> str | None:
    return exc.response.get("Error", {}).get("Code")


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _enable_capacity_manager(ec2, timeout_s=120.0, interval_s=5.0) -> None:
    """EnableCapacityManager, waiting out a disable still in progress: AWS refuses a second
    mutation with ConcurrentMutationLimitExceeded until the first one settles."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.enable_capacity_manager(OrganizationsAccess=False)
            return
        except ClientError as exc:
            if _code(exc) != "ConcurrentMutationLimitExceeded" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
