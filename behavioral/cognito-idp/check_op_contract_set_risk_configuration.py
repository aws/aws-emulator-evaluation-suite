"""op-contract-set-risk-configuration."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-set-risk-configuration"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetRiskConfiguration writes threat-protection config for a user pool; it is rejected
    outright for a user pool that doesn't exist."""
    cognito = ctx.client("cognito-idp")

    # Success path: a Plus-tier pool with AdvancedSecurityMode enabled accepts risk config.
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-riskcfg-"),
        UserPoolTier="PLUS",
        UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    resp = cognito.set_risk_configuration(
        UserPoolId=pool_id,
        CompromisedCredentialsRiskConfiguration={
            "Actions": {"EventAction": "BLOCK"},
            "EventFilter": ["SIGN_IN", "PASSWORD_CHANGE"],
        },
    )
    cfg = resp["RiskConfiguration"]["CompromisedCredentialsRiskConfiguration"]
    assert cfg["Actions"]["EventAction"] == "BLOCK", cfg
    assert set(cfg["EventFilter"]) == {"SIGN_IN", "PASSWORD_CHANGE"}, cfg

    described = cognito.describe_risk_configuration(UserPoolId=pool_id)["RiskConfiguration"]
    described_cfg = described["CompromisedCredentialsRiskConfiguration"]
    assert described_cfg["Actions"]["EventAction"] == "BLOCK", described_cfg
    assert set(described_cfg["EventFilter"]) == {"SIGN_IN", "PASSWORD_CHANGE"}, described_cfg

    # Error boundary: on real AWS, SetRiskConfiguration itself is not gated on the pool's
    # advanced-security add-on (that only affects whether risk is actually evaluated), so
    # the genuine, stable error boundary here is a user pool that does not exist at all.
    bogus_pool_id = pool_id[:-1] + ("0" if pool_id[-1] != "0" else "1")
    code, message = _error(
        lambda: cognito.set_risk_configuration(
            UserPoolId=bogus_pool_id,
            CompromisedCredentialsRiskConfiguration={"Actions": {"EventAction": "BLOCK"}},
        )
    )
    assert code == "ResourceNotFoundException", code
    expected = f"User pool {bogus_pool_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
