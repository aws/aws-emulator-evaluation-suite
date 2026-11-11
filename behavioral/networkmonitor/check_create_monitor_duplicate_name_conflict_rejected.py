"""create-monitor-duplicate-name-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-monitor-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateMonitor with an existing monitorName fails with ConflictException and the exact message
    and leaves the original aggregationPeriod 60; a monitor under an unused name is created and reads
    back with aggregationPeriod 30."""
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nwm-mon-")
    original = nm.create_monitor(monitorName=name, aggregationPeriod=60)
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))
    assert original["aggregationPeriod"] == 60, (
        f"positive control: expected aggregationPeriod 60, got {original['aggregationPeriod']!r}"
    )

    err = _error(lambda: nm.create_monitor(monitorName=name, aggregationPeriod=30))
    assert err["Code"] == "ConflictException", f"expected ConflictException, got {err['Code']!r}"
    expected = f"Existing monitor found for account {ctx.account} and monitorName {name}."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    unchanged = nm.get_monitor(monitorName=name)
    assert unchanged["aggregationPeriod"] == 60, "duplicate create attempt must not mutate the existing monitor"

    other_name = ctx.unique_name("sim2real-nwm-mon-")
    created = nm.create_monitor(monitorName=other_name, aggregationPeriod=30)
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=other_name))
    assert created["monitorName"] == other_name, (
        f"expected monitorName {other_name!r}, got {created['monitorName']!r}"
    )

    # terminal read: independent of the mutating CreateMonitor call that produced it
    fetched = nm.get_monitor(monitorName=other_name)
    assert fetched["monitorName"] == other_name and fetched["aggregationPeriod"] == 30, (
        f"GetMonitor must reflect the distinct-name monitor (name={other_name!r}, "
        f"aggregationPeriod=30), got name={fetched.get('monitorName')!r}, "
        f"aggregationPeriod={fetched.get('aggregationPeriod')!r}"
    )


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
