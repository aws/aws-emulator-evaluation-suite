"""create-group-duplicate-name-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-group-duplicate-name-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected CreateGroup to be rejected, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGroup with an already-used GroupName is rejected, the original group is untouched,
    and CreateGroup with a distinct name still succeeds in the same run (positive control)."""
    xr = ctx.client("xray")
    name = ctx.unique_name("sim2real-behav-xray-grp-")[:32].rstrip("-")
    xr.create_group(
        GroupName=name,
        FilterExpression='service("a")',
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=name))

    error = _client_error(
        lambda: xr.create_group(GroupName=name, FilterExpression='service("b")')
    )
    assert error.get("Code") == "InvalidRequestException", (
        f"expected InvalidRequestException, got {error!r}"
    )
    assert error.get("Message") == f"{name} already exists", (
        f"the refusal must name the colliding group, got {error!r}"
    )

    got = xr.get_group(GroupName=name)["Group"]
    assert got["FilterExpression"] == 'service("a")', got

    # Positive control: a CreateGroup with a genuinely distinct name still succeeds in this run,
    # so the rejection above is attributable to the duplicate name and not to anything else.
    control_name = ctx.unique_name("sim2real-behav-xray-ctl-")[:32].rstrip("-")
    control = xr.create_group(
        GroupName=control_name,
        FilterExpression='service("c")',
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Group"]
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=control_name))
    assert control["GroupName"] == control_name, control


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
