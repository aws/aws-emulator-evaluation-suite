"""get-monitor-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-monitor-not-found"
GROUP = "errors"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMonitor on a well-formed but never-created monitorName returns
    ResourceNotFoundException — and, via a positive control on a real monitor,
    this is specifically about the missing name and not GetMonitor failing outright."""
    nm = ctx.client("networkmonitor")

    # Positive control: GetMonitor must succeed on a monitor that genuinely exists,
    # so the rejection below can be attributed to the missing name specifically.
    real_name = ctx.unique_name("sim2real-nm-mon-")
    nm.create_monitor(monitorName=real_name, aggregationPeriod=30)
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=real_name))
    control = nm.get_monitor(monitorName=real_name)
    assert control["monitorName"] == real_name, (
        f"positive control failed: GetMonitor on a real monitor returned {control.get('monitorName')!r}"
    )

    missing_name = ctx.unique_name("sim2real-nm-missing-")
    err = _error(lambda: nm.get_monitor(monitorName=missing_name))
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
