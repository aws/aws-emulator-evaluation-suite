"""risk-configuration-set-and-describe-without-addon."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "risk-configuration-set-and-describe-without-addon"
GROUP = 'state-machine'
SERVICES = ['cognito-idp']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a pool without the advanced-security add-on, SetRiskConfiguration is accepted and
    DescribeRiskConfiguration returns the compromised-credentials EventAction BLOCK that was set."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    c.set_risk_configuration(
        UserPoolId=pool_id,
        CompromisedCredentialsRiskConfiguration={"Actions": {"EventAction": "BLOCK"}},
    )

    got = c.describe_risk_configuration(UserPoolId=pool_id)["RiskConfiguration"]
    assert (
        got.get("CompromisedCredentialsRiskConfiguration", {})
        .get("Actions", {})
        .get("EventAction")
        == "BLOCK"
    ), got


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
