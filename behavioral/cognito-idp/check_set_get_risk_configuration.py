"""set-get-risk-configuration."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "set-get-risk-configuration"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetRiskConfiguration values for adaptive authentication persist and are returned by DescribeRiskConfiguration."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-risk-pool"),
        DeletionProtection="INACTIVE",
        UserPoolTier="PLUS",
        UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-risk-pool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    compromised_cfg = {
        "EventFilter": ["SIGN_IN", "PASSWORD_CHANGE"],
        "Actions": {"EventAction": "BLOCK"},
    }

    set_resp = cognito.set_risk_configuration(
        UserPoolId=pool_id,
        CompromisedCredentialsRiskConfiguration=compromised_cfg,
    )
    set_cfg = set_resp["RiskConfiguration"]["CompromisedCredentialsRiskConfiguration"]
    assert set_cfg["Actions"]["EventAction"] == "BLOCK", set_cfg
    assert sorted(set_cfg["EventFilter"]) == ["PASSWORD_CHANGE", "SIGN_IN"], set_cfg

    describe_resp = cognito.describe_risk_configuration(UserPoolId=pool_id)
    got_cfg = describe_resp["RiskConfiguration"][
        "CompromisedCredentialsRiskConfiguration"
    ]
    assert got_cfg["Actions"]["EventAction"] == "BLOCK", got_cfg
    assert sorted(got_cfg["EventFilter"]) == ["PASSWORD_CHANGE", "SIGN_IN"], got_cfg


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
