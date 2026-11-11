"""create-schedule-group-name-length-exceeded-rejected."""
from __future__ import annotations

from typing import Any

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-group-name-length-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A ScheduleGroup Name exceeding the documented 64-character maximum is
    rejected with ValidationException, no group is created under that name, and
    an otherwise-identical valid-length name succeeds."""
    # Local parameter validation is off so the over-length value reaches the endpoint.
    scheduler = ctx.client("scheduler", config=Config(parameter_validation=False))

    base = ctx.unique_name("sim2real-sg-len-")
    long_name = base + "x" * max(0, 70 - len(base))
    assert len(long_name) > 64, "test name must actually exceed the 64-char limit"

    code, message = _error(lambda: scheduler.create_schedule_group(Name=long_name))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        f"1 validation error detected: Value '{long_name}' at 'name' failed to satisfy constraint: "
        "Member must have length less than or equal to 64"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listing = scheduler.list_schedule_groups(NamePrefix=base)
    names = [g["Name"] for g in listing.get("ScheduleGroups", [])]
    assert long_name not in names, "over-length group name must not have been created"

    good_name = ctx.unique_name("sim2real-sg-ok-")
    resp = scheduler.create_schedule_group(Name=good_name)
    ctx.on_cleanup(lambda: scheduler.delete_schedule_group(Name=good_name))
    assert resp["ScheduleGroupArn"], "valid-length name must succeed and return an ARN"
    got = scheduler.get_schedule_group(Name=good_name)
    assert got["State"] == "ACTIVE", f"expected ACTIVE, got {got['State']!r}"


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
