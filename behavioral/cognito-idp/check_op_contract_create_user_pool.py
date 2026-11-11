"""op-contract-createUserPool."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-createUserPool"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUserPool returns the requested policy/name on success and rejects an
    MfaConfiguration of "ON" when the request omits the required SmsConfiguration."""
    cognito = ctx.client("cognito-idp")

    # success path
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 10,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        },
        MfaConfiguration="OFF",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    assert pool["Policies"]["PasswordPolicy"]["MinimumLength"] == 10, pool["Policies"]
    assert pool["MfaConfiguration"] == "OFF", pool["MfaConfiguration"]
    assert pool["Arn"].endswith(pool_id), pool["Arn"]

    described = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert described["Policies"]["PasswordPolicy"]["MinimumLength"] == 10, described["Policies"]

    # distinct error boundary: MfaConfiguration="ON" requires an SmsConfiguration in
    # the same request -- the model's own docs are explicit that omitting it returns
    # InvalidParameterException. Unlike PasswordPolicy.MinimumLength's range (which
    # botocore's shape validation enforces client-side, so that call never reaches
    # the service), nothing in the request shape rules out ON with no
    # SmsConfiguration, so this one is a real service-side rejection.
    bad_pool_name = ctx.unique_name("sim2real-pool-bad-")
    try:
        cognito.create_user_pool(
            PoolName=bad_pool_name,
            MfaConfiguration="ON",
        )
        raised = None
    except ClientError as err:
        raised = err
    assert raised is not None, "expected MfaConfiguration=ON with no SmsConfiguration to be rejected"
    assert raised.response["Error"]["Code"] == "InvalidParameterException", raised.response["Error"]
    assert raised.response["Error"].get("Message") == "SMS configuration and Auto verification for phone_number are required when MFA is required/optional", raised.response["Error"].get("Message")

    # effect-absent, via an independent read at the destination: the rejected call
    # must not have left a pool behind. If it did (a partial-failure orphan), adopt
    # it into this run's cleanup so the account still ends up clean.
    leaked = [
        p for p in cognito.list_user_pools(MaxResults=60)["UserPools"] if p["Name"] == bad_pool_name
    ]
    for p in leaked:
        ctx.on_cleanup(lambda _id=p["Id"]: cognito.delete_user_pool(UserPoolId=_id))
    assert not leaked, f"rejected CreateUserPool left a pool behind: {leaked}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
