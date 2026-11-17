"""create-user-pool-sms-role-without-sns-publish-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-user-pool-sms-role-without-sns-publish-rejected"
GROUP = "resource-binding"
SERVICES = ["cognito-idp", "iam", "sns"]


def _trust_policy(ctx, external_id: str) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cognito-idp.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": external_id,
                    "aws:SourceAccount": ctx.account,
                },
                "ArnLike": {
                    "aws:SourceArn": f"arn:aws:cognito-idp:{ctx.region}:{ctx.account}:userpool/*",
                },
            },
        }],
    })


def _purge_role(iam, role):
    """Detach and delete every inline policy on ``role``, then the role itself."""
    try:
        for name in iam.list_role_policies(RoleName=role)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role, PolicyName=name)
        iam.delete_role(RoleName=role)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _mint_role(ctx, iam, prefix: str, external_id: str, *, grant_publish: bool) -> str:
    """A fresh role trusting cognito-idp.amazonaws.com with ``external_id``; returns its ARN."""
    name = ctx.unique_name(prefix)
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_trust_policy(ctx, external_id),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _purge_role(iam, name))
    if grant_publish:
        iam.put_role_policy(RoleName=name, PolicyName="publish", PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sns:Publish", "Resource": "*"}],
        }))
    return arn


def _create_pool_tolerating_trust_propagation(cidp, pool_name: str, role_arn: str,
                                               external_id: str, *, budget_s: float = 90.0,
                                               interval_s: float = 3.0):
    """CreateUserPool, retrying only InvalidSmsRoleTrustRelationshipException: the role's trust
    policy was just created and Cognito's AssumeRole probe can lag IAM propagation.

    Any other outcome (success, or a different error) returns or raises immediately.
    """
    deadline = time.monotonic() + budget_s
    while True:
        try:
            return cidp.create_user_pool(
                PoolName=pool_name,
                SmsConfiguration={"SnsCallerArn": role_arn, "ExternalId": external_id},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSmsRoleTrustRelationshipException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUserPool binds an SMS role that can publish to SNS, and refuses one that cannot.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-sms-settings.html
    """
    cidp = ctx.client("cognito-idp")
    iam = ctx.client("iam")

    good_external_id = ctx.unique_name("sim2real-xsvc-cidp-eid-good")
    good_role = _mint_role(ctx, iam, "sim2real-xsvc-cidp-good-role-", good_external_id,
                            grant_publish=True)
    good_pool_name = ctx.unique_name("sim2real-xsvc-cidp-pool-good-")

    good_pool = _create_pool_tolerating_trust_propagation(
        cidp, good_pool_name, good_role, good_external_id,
    )
    good_pool_id = good_pool["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cidp.delete_user_pool(UserPoolId=good_pool_id))

    described = cidp.describe_user_pool(UserPoolId=good_pool_id)["UserPool"]
    assert described["SmsConfiguration"]["SnsCallerArn"] == good_role, (
        f"DescribeUserPool echoed SnsCallerArn {described['SmsConfiguration'].get('SnsCallerArn')!r}, "
        f"expected the role that was bound at create {good_role!r}"
    )

    bad_external_id = ctx.unique_name("sim2real-xsvc-cidp-eid-bad")
    bad_role = _mint_role(ctx, iam, "sim2real-xsvc-cidp-bad-role-", bad_external_id,
                           grant_publish=False)
    bad_pool_name = ctx.unique_name("sim2real-xsvc-cidp-pool-bad-")

    try:
        _create_pool_tolerating_trust_propagation(cidp, bad_pool_name, bad_role, bad_external_id)
        raise AssertionError(
            f"CreateUserPool succeeded with a role {bad_role!r} that grants no sns:Publish"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"]["Message"]
        assert code == "InvalidSmsRoleAccessPolicyException", (
            f"expected InvalidSmsRoleAccessPolicyException for a role with no sns:Publish grant, "
            f"got {code!r}: {message!r}"
        )
        assert message == "Role does not have permission to publish with SNS", (
            f"unexpected message for InvalidSmsRoleAccessPolicyException: {message!r}"
        )

    paginator = cidp.get_paginator("list_user_pools")
    names = {p["Name"] for page in paginator.paginate(MaxResults=60) for p in page["UserPools"]}
    assert bad_pool_name not in names, (
        f"a user pool named {bad_pool_name!r} exists even though its CreateUserPool was refused"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
