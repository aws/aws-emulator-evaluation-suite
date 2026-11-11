"""op-contract-describe-risk-configuration."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "op-contract-describe-risk-configuration"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeRiskConfiguration omits RiskConfiguration on a never-configured pool without the
    advanced security add-on; an AccountTakeoverRiskConfiguration write on that pool is accepted
    and read back, and a write on an add-on pool is readable."""
    idp = ctx.client("cognito-idp")
    tags_kwarg = {"UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}}

    try:
        secured_pool_id = idp.create_user_pool(
            PoolName=ctx.unique_name("sim2real-behav-secure-"),
            UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"},
            **tags_kwarg,
        )["UserPool"]["Id"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "FeatureUnavailableInTierException":
            raise AssertionError("advanced security (threat protection) not available for this account/tier")
        raise
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=secured_pool_id))

    plain_pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-plain-"), **tags_kwarg
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=plain_pool_id))

    # The add-on can take seconds to propagate after CreateUserPool (transient
    # UserPoolAddOnNotEnabledException), so poll the write; a config is written first because
    # a never-configured pool omits RiskConfiguration from the read.
    _poll_set_risk_configuration(idp, secured_pool_id)
    risk = idp.describe_risk_configuration(UserPoolId=secured_pool_id)["RiskConfiguration"]
    assert risk["UserPoolId"] == secured_pool_id, risk

    # The read is not gated by the add-on; a never-configured pool omits the member entirely.
    response_plain = idp.describe_risk_configuration(UserPoolId=plain_pool_id)
    assert "RiskConfiguration" not in response_plain, response_plain

    # An AccountTakeoverRiskConfiguration-only write is accepted without the add-on.
    idp.set_risk_configuration(
        UserPoolId=plain_pool_id,
        AccountTakeoverRiskConfiguration={
            "Actions": {
                "LowAction": {"Notify": False, "EventAction": "NO_ACTION"},
                "MediumAction": {"Notify": False, "EventAction": "NO_ACTION"},
                "HighAction": {"Notify": False, "EventAction": "NO_ACTION"},
            }
        },
    )
    response_plain_after = idp.describe_risk_configuration(UserPoolId=plain_pool_id)["RiskConfiguration"]
    persisted_actions = response_plain_after["AccountTakeoverRiskConfiguration"]["Actions"]
    assert persisted_actions["LowAction"]["EventAction"] == "NO_ACTION", persisted_actions
    assert persisted_actions["MediumAction"]["EventAction"] == "NO_ACTION", persisted_actions
    assert persisted_actions["HighAction"]["EventAction"] == "NO_ACTION", persisted_actions


def _poll_set_risk_configuration(idp, pool_id: str, timeout: float = 30.0, interval: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    last_exc = None
    while time.monotonic() < deadline:
        try:
            idp.set_risk_configuration(
                UserPoolId=pool_id,
                CompromisedCredentialsRiskConfiguration={"Actions": {"EventAction": "NO_ACTION"}},
            )
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "UserPoolAddOnNotEnabledException":
                raise
            last_exc = e
            time.sleep(interval)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
