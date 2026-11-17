"""risk-configuration-client-override-scoped-to-one-client."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "risk-configuration-client-override-scoped-to-one-client"
GROUP = "risk-configuration"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_POOL_RANGE = "192.0.2.0/24"
_CLIENT_RANGE = "198.51.100.0/24"


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:representation", "plane:data", "dp:api")
def run(ctx) -> None:
    """A ClientId-scoped SetRiskConfiguration overrides the pool default for that one app client
    only; the pool-level configuration and a sibling client's view of it are unaffected.
    """
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-riskscope-"),
        UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"},
        UserPoolTags=_TAGS,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_a = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-riskscope-a-")
    )["UserPoolClient"]["ClientId"]
    client_b = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-riskscope-b-")
    )["UserPoolClient"]["ClientId"]

    idp.set_risk_configuration(
        UserPoolId=pool_id,
        RiskExceptionConfiguration={"BlockedIPRangeList": [_POOL_RANGE]},
    )
    pool_level = idp.describe_risk_configuration(UserPoolId=pool_id)["RiskConfiguration"]
    assert pool_level["RiskExceptionConfiguration"]["BlockedIPRangeList"] == [_POOL_RANGE], (
        f"expected the pool-level BlockedIPRangeList to be [{_POOL_RANGE!r}], "
        f"got {pool_level['RiskExceptionConfiguration'].get('BlockedIPRangeList')!r}"
    )

    # Before either client has its own override, a ClientId-scoped read omits RiskConfiguration
    # entirely rather than falling back to the pool default -- the baseline both clients share.
    before_a = idp.describe_risk_configuration(UserPoolId=pool_id, ClientId=client_a)
    before_b = idp.describe_risk_configuration(UserPoolId=pool_id, ClientId=client_b)
    assert "RiskConfiguration" not in before_a, (
        f"expected no RiskConfiguration for a client with no override, got {before_a!r}"
    )
    assert "RiskConfiguration" not in before_b, (
        f"expected no RiskConfiguration for a client with no override, got {before_b!r}"
    )

    idp.set_risk_configuration(
        UserPoolId=pool_id,
        ClientId=client_a,
        RiskExceptionConfiguration={"BlockedIPRangeList": [_CLIENT_RANGE]},
    )
    after_a = idp.describe_risk_configuration(UserPoolId=pool_id, ClientId=client_a)["RiskConfiguration"]
    assert after_a["RiskExceptionConfiguration"]["BlockedIPRangeList"] == [_CLIENT_RANGE], (
        f"expected client_a's own override [{_CLIENT_RANGE!r}] to read back, "
        f"got {after_a['RiskExceptionConfiguration'].get('BlockedIPRangeList')!r}"
    )

    # The sibling client and the pool default must be untouched by client_a's override.
    after_b = idp.describe_risk_configuration(UserPoolId=pool_id, ClientId=client_b)
    assert "RiskConfiguration" not in after_b, (
        f"client_b's risk configuration changed after client_a received its own override: "
        f"expected still no RiskConfiguration, got {after_b!r}"
    )
    pool_level_after = idp.describe_risk_configuration(UserPoolId=pool_id)["RiskConfiguration"]
    assert pool_level_after["RiskExceptionConfiguration"]["BlockedIPRangeList"] == [_POOL_RANGE], (
        f"the pool-level BlockedIPRangeList changed after a client-level override was set: "
        f"got {pool_level_after['RiskExceptionConfiguration'].get('BlockedIPRangeList')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
