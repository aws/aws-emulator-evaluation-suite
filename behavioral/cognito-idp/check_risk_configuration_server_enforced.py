"""risk-configuration-server-enforced."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "risk-configuration-server-enforced"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetRiskConfiguration persists adaptive-auth thresholds unchanged by DescribeRiskConfiguration."""

    idp = ctx.client("cognito-idp")
    pool_id = _create_pool_with_advanced_security(ctx, idp)

    compromised = {
        "Actions": {"EventAction": "BLOCK"},
        "EventFilter": ["SIGN_IN", "PASSWORD_CHANGE"],
    }
    risk_exception = {
        "BlockedIPRangeList": ["10.0.0.0/24"],
        "SkippedIPRangeList": ["192.168.1.0/24"],
    }
    try:
        set_resp = idp.set_risk_configuration(
            UserPoolId=pool_id,
            CompromisedCredentialsRiskConfiguration=compromised,
            RiskExceptionConfiguration=risk_exception,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "UserPoolAddOnNotEnabledException":
            raise AssertionError(
                "unreachable: advanced security add-on not enabled for this account/tier"
            )
        raise

    set_cfg = set_resp["RiskConfiguration"]
    set_compromised = set_cfg["CompromisedCredentialsRiskConfiguration"]
    assert set_compromised["Actions"]["EventAction"] == "BLOCK", (
        f"expected SetRiskConfiguration response to echo EventAction=BLOCK, got {set_compromised}"
    )
    assert sorted(set_compromised["EventFilter"]) == ["PASSWORD_CHANGE", "SIGN_IN"], (
        f"expected SetRiskConfiguration response to echo the EventFilter we sent, got {set_compromised}"
    )
    set_exception = set_cfg["RiskExceptionConfiguration"]
    assert sorted(set_exception["BlockedIPRangeList"]) == ["10.0.0.0/24"], (
        f"expected SetRiskConfiguration response to echo BlockedIPRangeList, got {set_exception}"
    )

    desc = idp.describe_risk_configuration(UserPoolId=pool_id)["RiskConfiguration"]
    desc_compromised = desc["CompromisedCredentialsRiskConfiguration"]
    assert desc_compromised["Actions"]["EventAction"] == "BLOCK", (
        f"expected DescribeRiskConfiguration to persist EventAction=BLOCK, got {desc_compromised}"
    )
    assert sorted(desc_compromised["EventFilter"]) == ["PASSWORD_CHANGE", "SIGN_IN"], (
        f"expected DescribeRiskConfiguration to persist the EventFilter we sent, got {desc_compromised}"
    )
    desc_exception = desc["RiskExceptionConfiguration"]
    assert sorted(desc_exception["BlockedIPRangeList"]) == ["10.0.0.0/24"], (
        f"expected DescribeRiskConfiguration to persist BlockedIPRangeList, got {desc_exception}"
    )
    assert sorted(desc_exception["SkippedIPRangeList"]) == ["192.168.1.0/24"], (
        f"expected DescribeRiskConfiguration to persist SkippedIPRangeList, got {desc_exception}"
    )


def _create_pool_with_advanced_security(ctx, idp) -> str:

    name = ctx.unique_name("sim2real-behav-riskcfg-")
    try:
        resp = idp.create_user_pool(
            PoolName=name,
            UserPoolTier="PLUS",
            UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"},
            UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("FeatureUnavailableInTierException", "TierChangeNotAllowedException"):
            raise AssertionError(f"unreachable: advanced security unavailable in tier ({code})")
        raise
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
