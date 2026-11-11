"""create-group-defaults."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-group-defaults"
GROUP = 'groups'
SERVICES = ['xray']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGroup persists GroupName/FilterExpression and issues a well-formed GroupARN."""
    xr = ctx.client("xray")
    name = ctx.unique_name("sim2real-behav-xray-grp-")[:32].rstrip("-")
    resp = xr.create_group(GroupName=name, FilterExpression='service("test")')
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=name))
    group = resp["Group"]
    assert group["GroupName"] == name, group
    assert group["FilterExpression"] == 'service("test")', group
    # Real GroupARN is "arn:aws:xray:<region>:<account>:group/<name>/<id>" -- the name is
    # followed by a generated id segment, never the ARN's terminal component.
    assert f"group/{name}/" in group["GroupARN"], group

    got = xr.get_group(GroupName=name)["Group"]
    assert got["GroupName"] == name, got
    assert got["FilterExpression"] == 'service("test")', got
    assert got["GroupARN"] == group["GroupARN"], got


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
