"""create-group-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-group-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGroup with a GroupName that already exists is rejected with
    InvalidRequestException, the original group's FilterExpression is left untouched, and a
    CreateGroup with a distinct name still succeeds (positive control in the same run)."""
    xray = ctx.client("xray")
    group_name = ctx.unique_name("sim2real-xr-dup-")
    original_filter = 'service("first-owner")'

    second_filter = 'service("second-owner")'

    xray.create_group(GroupName=group_name, FilterExpression=original_filter, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_if_present(xray, group_name))

    error = _client_error(
        lambda: xray.create_group(GroupName=group_name, FilterExpression=second_filter)
    )
    assert error.get("Code") == "InvalidRequestException", (
        f"expected CreateGroup with a duplicate GroupName to be rejected with "
        f"InvalidRequestException, got {error!r}"
    )
    assert error.get("HTTPStatusCode") == 400, f"expected HTTP 400 for the duplicate CreateGroup, got {error!r}"
    expected_message = f"{group_name} already exists"
    assert error.get("Message") == expected_message, f'expected the message {expected_message!r}, got {error.get("Message")!r}'

    # The effect is absent: the original group's filter expression was not overwritten.
    unchanged = xray.get_group(GroupName=group_name)["Group"]
    assert unchanged["FilterExpression"] == original_filter, (
        f"expected the original FilterExpression {original_filter!r} to survive the rejected "
        f"duplicate create, got {unchanged['FilterExpression']!r}"
    )

    # Positive control: a CreateGroup with a genuinely new name still succeeds in this run,
    # proven by an independent read at the destination rather than the mutating call's own echo.
    control_name = ctx.unique_name("sim2real-xr-ctrl-")
    xray.create_group(GroupName=control_name, FilterExpression='service("control-owner")', Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_if_present(xray, control_name))
    control = xray.get_group(GroupName=control_name)["Group"]
    assert control["GroupName"] == control_name, (
        f"expected the control group {control_name!r} to be independently readable after "
        f"creation, got {control!r}"
    )

    # Restore: once the name is free, the identical second CreateGroup succeeds with its filter.
    xray.delete_group(GroupName=group_name)
    xray.create_group(GroupName=group_name, FilterExpression=second_filter)
    replaced = xray.get_group(GroupName=group_name)["Group"]
    assert replaced["FilterExpression"] == second_filter, (
        f"expected the re-created group to carry {second_filter!r}, got {replaced['FilterExpression']!r}"
    )


def _client_error(fn):
    """Call fn(); return its ClientError Error dict plus the HTTPStatusCode. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a duplicate GroupName that real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return {**exc.response["Error"], "HTTPStatusCode": status}
    raise AssertionError(
        f"expected CreateGroup with a duplicate GroupName to be rejected, but it SUCCEEDED "
        f"and returned {result!r}"
    )


def _delete_if_present(xray, name):
    try:
        xray.delete_group(GroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidRequestException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
