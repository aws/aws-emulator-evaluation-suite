"""monitor-name-length-boundary-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "monitor-name-length-boundary-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A 201-character monitorName fails CreateMonitor with BadRequestException and GetMonitor with
    ValidationException, both with the exact message; a 200-character name is created and reads back."""
    nm = ctx.client("networkmonitor")
    too_long_name = "a" * 201

    err = _error(lambda: nm.create_monitor(monitorName=too_long_name, aggregationPeriod=30))
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err['Code']!r}"
    expected = "Invalid request body"
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # an over-length name also fails request validation on lookup
    lookup = _error(lambda: nm.get_monitor(monitorName=too_long_name))
    assert lookup["Code"] == "ValidationException", f"expected ValidationException, got {lookup['Code']!r}"
    expected = f"1 validation error detected: Value '{too_long_name}' at 'monitorName' failed to satisfy constraint: Member must have length less than or equal to 200"
    assert lookup["Message"] == expected, f"expected message {expected!r}, got {lookup['Message']!r}"

    # positive control: a name at exactly the 200-char boundary is accepted
    prefix = ctx.unique_name("sim2real-nm-")
    boundary_name = prefix + ("b" * (200 - len(prefix)))
    assert len(boundary_name) == 200, f"test setup bug: boundary name is {len(boundary_name)} chars, not 200"
    created = nm.create_monitor(
        monitorName=boundary_name, aggregationPeriod=30, tags={"sim2real": "true"}
    )
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=boundary_name))
    assert created["monitorName"] == boundary_name, (
        f"create response echoed {created['monitorName']!r}, expected {boundary_name!r}"
    )

    # independent read at the destination: the boundary-length monitor really exists
    fetched = nm.get_monitor(monitorName=boundary_name)
    assert fetched["monitorName"] == boundary_name, (
        f"get_monitor returned {fetched['monitorName']!r} for a name it should have accepted, "
        f"expected {boundary_name!r}"
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
