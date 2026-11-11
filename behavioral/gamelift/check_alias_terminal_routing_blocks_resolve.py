"""alias-terminal-routing-blocks-resolve."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "alias-terminal-routing-blocks-resolve"
GROUP = "state"
SERVICES = ["gamelift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResolveAlias returns the FleetId of a SIMPLE alias, fails with TerminalRoutingStrategyException and the
    alias's terminal message once UpdateAlias makes it TERMINAL, and resolves again after it is set back to
    SIMPLE.
    """
    gl = ctx.client("gamelift")
    name = ctx.unique_name("sim2real-alias-term-")
    bogus_fleet_id = "fleet-00000000-0000-0000-0000-000000000000"

    alias = gl.create_alias(
        Name=name,
        RoutingStrategy={"Type": "SIMPLE", "FleetId": bogus_fleet_id},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Alias"]
    alias_id = alias["AliasId"]
    ctx.on_cleanup(lambda: gl.delete_alias(AliasId=alias_id))

    # Positive control: resolve succeeds on this alias before we break it, so the later
    # exception can only be attributed to the TERMINAL transition, not to resolve being
    # universally broken.
    resolved = gl.resolve_alias(AliasId=alias_id)
    assert resolved["FleetId"] == bogus_fleet_id, (
        f"positive control: expected ResolveAlias to echo {bogus_fleet_id}, got {resolved!r}"
    )

    # Break exactly one thing: flip the routing strategy to TERMINAL.
    terminal_message = "This alias is retired."
    updated = gl.update_alias(
        AliasId=alias_id,
        RoutingStrategy={"Type": "TERMINAL", "Message": terminal_message},
    )["Alias"]
    assert updated["RoutingStrategy"]["Type"] == "TERMINAL", (
        f"expected UpdateAlias to apply TERMINAL, got {updated['RoutingStrategy']!r}"
    )

    code, message = _error(lambda: gl.resolve_alias(AliasId=alias_id))
    assert code == "TerminalRoutingStrategyException", (
        f"expected TerminalRoutingStrategyException on a TERMINAL alias, got {code!r}"
    )
    # The refusal carries the alias's own TERMINAL message verbatim.
    assert message == terminal_message, f"expected message {terminal_message!r}, got {message!r}"

    # Effect absent: the alias itself remains fully describable -- only resolution is blocked.
    described = gl.describe_alias(AliasId=alias_id)["Alias"]
    assert described["AliasId"] == alias_id, (
        f"expected DescribeAlias to still find {alias_id}, got {described.get('AliasId')!r}"
    )
    assert described["RoutingStrategy"]["Type"] == "TERMINAL", (
        f"expected the described strategy to still be TERMINAL, got {described['RoutingStrategy']!r}"
    )

    # Restore: flipping back to SIMPLE lifts the restriction -- it tracks state, not identity.
    gl.update_alias(
        AliasId=alias_id,
        RoutingStrategy={"Type": "SIMPLE", "FleetId": bogus_fleet_id},
    )
    restored = gl.resolve_alias(AliasId=alias_id)
    assert restored["FleetId"] == bogus_fleet_id, (
        f"expected restoring SIMPLE to lift the TERMINAL block, got {restored!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
