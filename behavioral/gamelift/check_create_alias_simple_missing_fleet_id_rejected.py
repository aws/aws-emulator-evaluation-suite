"""create-alias-simple-missing-fleet-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-alias-simple-missing-fleet-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["gamelift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAlias with RoutingStrategy.Type=SIMPLE but no FleetId is rejected with
    InvalidRequestException, and no alias is persisted under that name -- while a
    TERMINAL alias (no FleetId required) succeeds in the very same run."""
    gl = ctx.client("gamelift")
    bad_name = ctx.unique_name("sim2real-alias-badsimple-")

    code = _error_code(
        lambda: gl.create_alias(Name=bad_name, RoutingStrategy={"Type": "SIMPLE"})
    )
    assert code == "InvalidRequestException", (
        f"CreateAlias with RoutingStrategy.Type=SIMPLE and no FleetId was refused with "
        f"{code!r}, not InvalidRequestException"
    )

    # Effect absent: nothing was created under that name.
    matches = gl.list_aliases(Name=bad_name)["Aliases"]
    assert matches == [], (
        f"the rejected SIMPLE alias {bad_name!r} is nonetheless visible in ListAliases: "
        f"{matches!r}"
    )

    # Positive control: the same operation succeeds for a routing strategy that
    # doesn't require a FleetId.
    good_name = ctx.unique_name("sim2real-alias-goodterminal-")
    good = gl.create_alias(
        Name=good_name,
        RoutingStrategy={"Type": "TERMINAL", "Message": "control alias"},
        Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral"}],
    )["Alias"]
    ctx.on_cleanup(lambda: gl.delete_alias(AliasId=good["AliasId"]))
    assert good["RoutingStrategy"]["Type"] == "TERMINAL", (
        f"CreateAlias with a TERMINAL routing strategy and no FleetId did not succeed as "
        f"expected: {good['RoutingStrategy']!r}"
    )

    # Terminal read: an independent DescribeAlias confirms the control alias is really
    # persisted, not just echoed back in the CreateAlias response.
    described = gl.describe_alias(AliasId=good["AliasId"])["Alias"]
    assert described["RoutingStrategy"]["Type"] == "TERMINAL", (
        f"DescribeAlias for {good['AliasId']!r} reports RoutingStrategy "
        f"{described['RoutingStrategy']!r}, not the TERMINAL strategy it was created with"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError(
        f"expected a ClientError but the call succeeded and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
