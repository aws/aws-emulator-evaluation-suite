"""set-risk-configuration-foreign-client-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-risk-configuration-foreign-client-rejected"
GROUP = "risk-configuration"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_RANGE = "203.0.113.0/24"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """SetRiskConfiguration and DescribeRiskConfiguration reject a ClientId that belongs to a
    different user pool, and the target pool's own risk configuration stays what it was.
    """
    idp = ctx.client("cognito-idp")
    own_pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-riskforeign-own-"),
        UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"},
        UserPoolTags=_TAGS,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=own_pool_id))
    own_client_id = idp.create_user_pool_client(
        UserPoolId=own_pool_id, ClientName=ctx.unique_name("sim2real-behav-riskforeign-ownc-")
    )["UserPoolClient"]["ClientId"]

    other_pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-riskforeign-other-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=other_pool_id))
    foreign_client_id = idp.create_user_pool_client(
        UserPoolId=other_pool_id, ClientName=ctx.unique_name("sim2real-behav-riskforeign-otherc-")
    )["UserPoolClient"]["ClientId"]

    # Positive control: a client that really belongs to own_pool_id is accepted.
    idp.set_risk_configuration(
        UserPoolId=own_pool_id,
        ClientId=own_client_id,
        RiskExceptionConfiguration={"BlockedIPRangeList": [_RANGE]},
    )
    control = idp.describe_risk_configuration(UserPoolId=own_pool_id, ClientId=own_client_id)[
        "RiskConfiguration"
    ]
    assert control["RiskExceptionConfiguration"]["BlockedIPRangeList"] == [_RANGE], (
        f"positive control: expected [{_RANGE!r}] for the pool's own client, "
        f"got {control['RiskExceptionConfiguration'].get('BlockedIPRangeList')!r}"
    )

    set_code, set_message = _error(
        lambda: idp.set_risk_configuration(
            UserPoolId=own_pool_id,
            ClientId=foreign_client_id,
            RiskExceptionConfiguration={"BlockedIPRangeList": [_RANGE]},
        )
    )
    assert set_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException setting risk config for a client of a different "
        f"pool, got {set_code!r}"
    )
    set_expected = f"User pool client {foreign_client_id} does not exist in user pool {own_pool_id}."
    assert set_message == set_expected, f"expected message {set_expected!r}, got {set_message!r}"

    describe_code, describe_message = _error(
        lambda: idp.describe_risk_configuration(UserPoolId=own_pool_id, ClientId=foreign_client_id)
    )
    assert describe_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException describing risk config for a client of a different "
        f"pool, got {describe_code!r}"
    )
    assert describe_message == set_expected, f"expected message {set_expected!r}, got {describe_message!r}"

    # The target pool's own client-level configuration must be unaffected by the rejected calls.
    unchanged = idp.describe_risk_configuration(UserPoolId=own_pool_id, ClientId=own_client_id)[
        "RiskConfiguration"
    ]
    assert unchanged["RiskExceptionConfiguration"]["BlockedIPRangeList"] == [_RANGE], (
        f"the pool's own client-level configuration changed after the rejected foreign-client "
        f"calls: got {unchanged['RiskExceptionConfiguration'].get('BlockedIPRangeList')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
