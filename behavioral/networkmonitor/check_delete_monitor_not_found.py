"""delete-monitor-not-found."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-monitor-not-found"
GROUP = "errors"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteMonitor on a never-created monitorName fails with ResourceNotFoundException and the
    exact message, while deleting a real monitor succeeds."""
    nm = ctx.client("networkmonitor")

    control_name = ctx.unique_name("sim2real-nm-control-")
    nm.create_monitor(monitorName=control_name, aggregationPeriod=60, tags={"purpose": "sim2real-control"})
    ctx.on_cleanup(lambda: _delete_if_present(nm, control_name))
    nm.delete_monitor(monitorName=control_name)

    missing_name = ctx.unique_name("sim2real-nm-missing-")
    err = _error(lambda: nm.delete_monitor(monitorName=missing_name))
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


def _delete_if_present(nm, monitor_name):
    from botocore.exceptions import ClientError

    try:
        nm.delete_monitor(monitorName=monitor_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
