"""update-group-filter-expression-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-group-filter-expression-persists"
GROUP = 'groups'
SERVICES = ['xray']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGroup mutates FilterExpression and the change is visible on subsequent GetGroup."""
    xr = ctx.client("xray")
    name = ctx.unique_name("sim2real-behav-xray-grp-")[:32].rstrip("-")
    xr.create_group(GroupName=name, FilterExpression='service("a")')
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=name))

    xr.update_group(GroupName=name, FilterExpression='service("b")')

    got = xr.get_group(GroupName=name)["Group"]
    assert got["FilterExpression"] == 'service("b")', got

    listed = [g for page in xr.get_paginator("get_groups").paginate() for g in page["Groups"]]
    match = next((g for g in listed if g["GroupName"] == name), None)
    assert match is not None, "updated group missing from GetGroups"
    assert match["FilterExpression"] == 'service("b")', match


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
