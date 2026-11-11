"""custom-sms-sender-without-kms-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-sms-sender-without-kms-key-rejected"
GROUP = "lambda-config-validation"
SERVICES = ["cognito-idp", "kms"]


def _refusal(fn) -> tuple[str, str]:
    """Return the (code, message) of a call expected to be REJECTED.

    Raises when the call SUCCEEDS instead, naming what came back."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, which is the defect: {result!r}"
    )


def _pool_ids_named(cog, name) -> list[str]:
    """Ids of every user pool in the Region named ``name``."""
    ids = []
    for page in cog.get_paginator("list_user_pools").paginate(MaxResults=60):
        ids += [p["Id"] for p in page.get("UserPools", []) if p.get("Name") == name]
    return ids


def _delete_pools_named(cog, name) -> None:
    """Teardown for a pool a refused create should never have made; a failed delete raises."""
    for pool_id in _pool_ids_named(cog, name):
        try:
            cog.delete_user_pool(UserPoolId=pool_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


@tags("axis:rejection", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CustomSMSSender with no KMSKeyID is refused at pool creation and no pool is created;
    the same LambdaConfig with a KMSKeyID is accepted and stored unchanged.
    """
    cog = ctx.client("cognito-idp")
    kms = ctx.client("kms")

    fn_arn = (f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:"
             f"{ctx.unique_name('sim2real-xsvc-fn-')}")

    refused_name = ctx.unique_name("sim2real-xsvc-pool-nokey-")
    ctx.on_cleanup(lambda: _delete_pools_named(cog, refused_name))
    refused = _refusal(lambda: cog.create_user_pool(
        PoolName=refused_name,
        LambdaConfig={"CustomSMSSender": {"LambdaVersion": "V1_0", "LambdaArn": fn_arn}},
        UserPoolTags={"sim2real:managed": "true"},
    ))
    assert refused == (
        "InvalidParameterException",
        "KMSKeyId parameter is required when Custom SMS/Email Lambda trigger is used.",
    ), f"CustomSMSSender with no KMSKeyID was refused with {refused!r}"
    # Effect absent: the refused CreateUserPool left no pool behind.
    left_behind = _pool_ids_named(cog, refused_name)
    assert not left_behind, f"the refused CreateUserPool still created pool(s) {left_behind!r}"

    key_arn = kms.create_key(
        Description="sim2real-xsvc-cognito custom sms sender code key",
        KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    pool = cog.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-pool-withkey-"),
        LambdaConfig={"CustomSMSSender": {"LambdaVersion": "V1_0", "LambdaArn": fn_arn},
                      "KMSKeyID": key_arn},
        UserPoolTags={"sim2real:managed": "true"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cog.delete_user_pool(UserPoolId=pool_id))

    lambda_config = pool["LambdaConfig"]
    assert lambda_config.get("KMSKeyID") == key_arn, (
        f"the pool's LambdaConfig.KMSKeyID is {lambda_config.get('KMSKeyID')!r}, expected "
        f"{key_arn!r}"
    )
    assert lambda_config.get("CustomSMSSender", {}).get("LambdaArn") == fn_arn, (
        f"the pool's LambdaConfig.CustomSMSSender.LambdaArn is "
        f"{lambda_config.get('CustomSMSSender', {})!r}, expected LambdaArn {fn_arn!r}"
    )

    described = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]["LambdaConfig"]
    assert described.get("KMSKeyID") == key_arn, (
        f"DescribeUserPool reports LambdaConfig.KMSKeyID {described.get('KMSKeyID')!r}, "
        f"expected {key_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
