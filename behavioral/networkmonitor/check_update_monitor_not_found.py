"""update-monitor-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-monitor-not-found"
GROUP = "errors"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateMonitor on a never-created monitorName fails with ResourceNotFoundException and the exact
    message, while an update of a real monitor persists aggregationPeriod 60."""
    nm = ctx.client("networkmonitor")

    # positive control: UpdateMonitor succeeds and persists against a real monitor
    name = ctx.unique_name("sim2real-nm-mon-")
    nm.create_monitor(monitorName=name, aggregationPeriod=30, tags={"sim2real": "audit"})
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))
    nm.update_monitor(monitorName=name, aggregationPeriod=60)
    persisted = nm.get_monitor(monitorName=name)["aggregationPeriod"]
    assert persisted == 60, f"expected positive-control update to persist, got {persisted}"

    missing_name = ctx.unique_name("sim2real-nm-missing-")
    err = _error(lambda: nm.update_monitor(monitorName=missing_name, aggregationPeriod=60))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err['Code']!r}"
    expected = f"No existing monitor found for account {ctx.account} and monitorName {missing_name}."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"


def _error(fn):
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
