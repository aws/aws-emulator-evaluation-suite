"""op-contract-get-capacity-manager-metric-dimensions-dup."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-capacity-manager-metric-dimensions-dup"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCapacityManagerMetricDimensions fails with CapacityManager.Disabled and its exact message while
    Capacity Manager is off, and once enabled returns a list whose entries carry the requested GroupBy
    dimension; DryRun answers DryRunOperation with the standard message."""
    ec2 = ctx.client("ec2")
    end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=1)
    kwargs = dict(
        StartTime=start,
        EndTime=end,
        GroupBy=["instance-family"],
        MetricNames=["reservation-total-count"],
    )

    try:
        resp = ec2.get_capacity_manager_metric_dimensions(**kwargs)
    except ClientError as exc:
        assert _code(exc) == "CapacityManager.Disabled", (
            f"expected CapacityManager.Disabled for a not-yet-enabled account, got {_code(exc)!r}"
        )
        disabled_message = exc.response.get("Error", {}).get("Message")
        assert disabled_message == "Capacity Manager isn't enabled for this account.", (
            f"unexpected CapacityManager.Disabled message {disabled_message!r}"
        )
    else:
        results = resp["MetricDimensionResults"]
        assert isinstance(results, list)
        for entry in results:
            assert "InstanceFamily" in entry, (
                f"GroupBy=['instance-family'] entry missing InstanceFamily: {entry}"
            )

    code, message = _error(
        lambda: ec2.get_capacity_manager_metric_dimensions(DryRun=True, **kwargs)
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
