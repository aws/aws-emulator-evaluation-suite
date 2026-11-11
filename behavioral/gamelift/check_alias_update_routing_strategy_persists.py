"""alias-update-routing-strategy-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "alias-update-routing-strategy-persists"
GROUP = "state"
SERVICES = ["gamelift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAlias replaces the RoutingStrategy in place and bumps LastUpdatedTime;
    DescribeAlias reflects the new strategy, not the original one."""
    gl = ctx.client("gamelift")
    name = ctx.unique_name("sim2real-alias-upd-")
    created = gl.create_alias(
        Name=name,
        RoutingStrategy={"Type": "TERMINAL", "Message": "not yet routable"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Alias"]
    alias_id = created["AliasId"]
    ctx.on_cleanup(lambda: gl.delete_alias(AliasId=alias_id))
    original_updated = created["LastUpdatedTime"]

    new_fleet_id = "fleet-11111111-1111-1111-1111-111111111111"
    updated = gl.update_alias(
        AliasId=alias_id,
        RoutingStrategy={"Type": "SIMPLE", "FleetId": new_fleet_id},
    )["Alias"]

    assert updated["RoutingStrategy"]["Type"] == "SIMPLE"
    assert updated["RoutingStrategy"]["FleetId"] == new_fleet_id
    assert "Message" not in updated["RoutingStrategy"] or not updated["RoutingStrategy"].get("Message")

    described = gl.describe_alias(AliasId=alias_id)["Alias"]
    assert described["RoutingStrategy"]["Type"] == "SIMPLE"
    assert described["RoutingStrategy"]["FleetId"] == new_fleet_id
    assert described["LastUpdatedTime"] >= original_updated


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
