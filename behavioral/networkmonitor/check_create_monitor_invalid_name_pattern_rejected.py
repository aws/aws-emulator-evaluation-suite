"""create-monitor-invalid-name-pattern-rejected."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "create-monitor-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateMonitor sent with a monitorName containing a space and '!' (client-side validation off)
    fails with BadRequestException and the exact message and creates no monitor; a valid name is
    created."""
    nm = ctx.client("networkmonitor")
    unvalidated_nm = ctx.client("networkmonitor", config=Config(parameter_validation=False))
    bad_name = ctx.unique_name("sim2real nwm invalid ") + "!"

    err = _error(lambda: unvalidated_nm.create_monitor(monitorName=bad_name, aggregationPeriod=60))
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err['Code']!r}"
    expected = "Invalid request body"
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    listed = nm.list_monitors()["monitors"]
    assert not any(m["monitorName"] == bad_name for m in listed), "rejected monitor must not have been created"

    good_name = ctx.unique_name("sim2real-nwm-mon-")
    created = nm.create_monitor(monitorName=good_name, aggregationPeriod=60, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=good_name))
    assert created["monitorName"] == good_name


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
