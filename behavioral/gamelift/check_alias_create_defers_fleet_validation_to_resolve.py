"""alias-create-defers-fleet-validation-to-resolve."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "alias-create-defers-fleet-validation-to-resolve"
GROUP = "error-semantics"
SERVICES = ["gamelift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAlias with a SIMPLE routing strategy accepts a FleetId that does not exist, and ResolveAlias and
    DescribeAlias both return that stored FleetId: fleet existence is not validated by the Alias API.
    """
    gl = ctx.client("gamelift")
    name = ctx.unique_name("sim2real-alias-simple-")
    bogus_fleet_id = "fleet-00000000-0000-0000-0000-000000000000"

    alias = gl.create_alias(
        Name=name,
        RoutingStrategy={"Type": "SIMPLE", "FleetId": bogus_fleet_id},
        Tags=[{"Key": "sim2real", "Value": "alias-create-defers-fleet-validation-to-resolve"}],
    )["Alias"]
    alias_id = alias["AliasId"]
    ctx.on_cleanup(lambda: gl.delete_alias(AliasId=alias_id))

    assert alias["RoutingStrategy"]["Type"] == "SIMPLE", (
        f"expected SIMPLE routing, got {alias['RoutingStrategy']['Type']!r}"
    )
    assert alias["RoutingStrategy"]["FleetId"] == bogus_fleet_id, (
        f"expected CreateAlias to accept the bogus fleet id unvalidated, "
        f"got FleetId={alias['RoutingStrategy'].get('FleetId')!r}"
    )

    # The bogus fleet reference is never validated: ResolveAlias echoes it back,
    # and an independent DescribeAlias confirms the same unvalidated value persisted.
    resolved = gl.resolve_alias(AliasId=alias_id)
    assert resolved["FleetId"] == bogus_fleet_id, (
        f"expected ResolveAlias to echo the bogus fleet id unvalidated, "
        f"got FleetId={resolved.get('FleetId')!r}"
    )

    described = gl.describe_alias(AliasId=alias_id)["Alias"]
    assert described["RoutingStrategy"]["FleetId"] == bogus_fleet_id, (
        f"expected DescribeAlias to still show the bogus fleet id, "
        f"got FleetId={described['RoutingStrategy'].get('FleetId')!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
