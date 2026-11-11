"""update-monitor-invalid-aggregation-period-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-monitor-invalid-aggregation-period-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMonitor only accepts aggregationPeriod values of 30 or 60. An
    out-of-range value (45) is rejected with ValidationException, the persisted
    value is unchanged, and a valid value (60) still succeeds (positive control)."""
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nm-mon-")
    nm.create_monitor(monitorName=name, aggregationPeriod=30, tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))

    code, message = _error(lambda: nm.update_monitor(monitorName=name, aggregationPeriod=45))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "The aggregation period must be one of [30, 60]."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: aggregationPeriod was not changed by the rejected update
    unchanged = nm.get_monitor(monitorName=name)["aggregationPeriod"]
    assert unchanged == 30, f"rejected update mutated aggregationPeriod: {unchanged}"

    # positive control: a valid aggregationPeriod value is accepted and persists
    nm.update_monitor(monitorName=name, aggregationPeriod=60)
    updated = nm.get_monitor(monitorName=name)["aggregationPeriod"]
    assert updated == 60, f"expected aggregationPeriod 60 after valid update, got {updated}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
