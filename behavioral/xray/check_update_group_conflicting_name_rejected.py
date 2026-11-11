"""update-group-conflicting-name-rejected."""
from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-group-conflicting-name-rejected"
GROUP = "negative-classes"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateGroup naming one group by GroupName and another by GroupARN fails with
    InvalidRequestException "Provide either GroupName or GroupARN" and changes neither, while an
    update by GroupARN alone applies."""
    xray = ctx.client("xray")
    name_a = ctx.unique_name("sim2real-ga-")
    name_b = ctx.unique_name("sim2real-gb-")

    group_a = xray.create_group(GroupName=name_a, FilterExpression='service("a")')["Group"]
    ctx.on_cleanup(lambda arn=group_a["GroupARN"]: xray.delete_group(GroupARN=arn))
    group_b = xray.create_group(GroupName=name_b, FilterExpression='service("b")')["Group"]
    ctx.on_cleanup(lambda arn=group_b["GroupARN"]: xray.delete_group(GroupARN=arn))

    # conflicting identity: GroupName names group A while GroupARN points at group B
    code, message = _error_code(
        lambda: xray.update_group(
            GroupARN=group_b["GroupARN"],
            GroupName=name_a,
            FilterExpression='service("changed")',
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected_message = "Provide either GroupName or GroupARN"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: neither group's filter expression was touched by the rejected call
    refreshed_b = xray.get_group(GroupARN=group_b["GroupARN"])["Group"]
    assert refreshed_b["FilterExpression"] == 'service("b")', (
        f"rejected UpdateGroup must leave group B untouched, got {refreshed_b['FilterExpression']!r}"
    )
    refreshed_a = xray.get_group(GroupARN=group_a["GroupARN"])["Group"]
    assert refreshed_a["FilterExpression"] == 'service("a")', (
        f"rejected UpdateGroup must leave group A untouched, got {refreshed_a['FilterExpression']!r}"
    )

    # positive control: updating by a SINGLE identifier (GroupARN alone) still succeeds
    updated = xray.update_group(
        GroupARN=group_b["GroupARN"], FilterExpression='service("b-updated")'
    )["Group"]
    assert updated["FilterExpression"] == 'service("b-updated")', (
        f"single-identifier UpdateGroup must apply, got {updated['FilterExpression']!r}"
    )

    # terminal read: independent of the mutating UpdateGroup call, at GetGroup
    reread_b = xray.get_group(GroupARN=group_b["GroupARN"])["Group"]
    assert reread_b["FilterExpression"] == 'service("b-updated")', (
        f"GetGroup must reflect the single-identifier update, got {reread_b['FilterExpression']!r}"
    )


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


