"""get-ui-customization-cross-pool-access-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-ui-customization-cross-pool-access-denied"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal whose policy is scoped to one pool's ARN gets AccessDeniedException (not
    Cognito's token-level NotAuthorizedException) calling GetUICustomization on another pool
    in the same account, while succeeding on the pool it was granted."""
    cognito = ctx.client("cognito-idp")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    pool_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    pool_a = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-a-"), UserPoolTags=pool_tags
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_a))
    pool_b_desc = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-b-"), UserPoolTags=pool_tags
    )["UserPool"]
    pool_b = pool_b_desc["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_b))

    # GetUICustomization requires the pool to have an associated (classic hosted UI) domain,
    # otherwise every call -- regardless of IAM authorization -- fails with
    # InvalidParameterException before authorization semantics are even reachable.
    domain_a = ctx.unique_name("sim2real-behav-domain-a").lower().replace("_", "-")
    cognito.create_user_pool_domain(Domain=domain_a, UserPoolId=pool_a)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=domain_a, UserPoolId=pool_a))

    account_id = sts.get_caller_identity()["Account"]
    pool_a_arn = f"arn:aws:cognito-idp:{ctx.region}:{account_id}:userpool/{pool_a}"

    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    def _delete_role():
        iam.delete_role_policy(RoleName=role_name, PolicyName="scoped-cognito-read")
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)

    scoped_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "cognito-idp:GetUICustomization",
                "Resource": pool_a_arn,
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="scoped-cognito-read", PolicyDocument=json.dumps(scoped_policy)
    )

    scoped_client = _poll_until(
        lambda: _try_scoped_client(ctx, sts, role_arn),
        lambda c: c is not None,
        timeout_s=30.0,
        interval_s=2.0,
        description="the freshly-created role becomes assumable",
    )

    # positive control: the scoped principal can read the pool it was granted, allowing for
    # IAM policy propagation delay and for the domain just created on pool_a to become visible
    _poll_until(
        lambda: _succeeds(lambda: scoped_client.get_ui_customization(UserPoolId=pool_a)),
        lambda ok: ok,
        timeout_s=60.0,
        interval_s=3.0,
        description="the granted pool's GetUICustomization succeeding for the scoped principal",
    )

    # negative: the same principal is denied against the pool it was never granted
    denied_code, denied_message = _expect_denied(
        lambda: scoped_client.get_ui_customization(UserPoolId=pool_b)
    )
    assert denied_code == "AccessDeniedException", f"expected AccessDeniedException, got {denied_code}"
    caller_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME}"
    expected = (
        f"User: {caller_arn} is not authorized to perform: cognito-idp:GetUICustomization on "
        f"resource: {pool_b_desc['Arn']} because no identity-based policy allows the "
        "cognito-idp:GetUICustomization action"
    )
    assert denied_message == expected, f"expected message {expected!r}, got {denied_message!r}"


_SESSION_NAME = "sim2real-cross-pool"


def _succeeds(fn) -> bool:
    """True when fn() returns; False when it raises a ClientError."""
    try:
        fn()
    except ClientError:
        return False
    return True


def _expect_denied(fn):
    """Return the (code, message) error; an unexpected SUCCESS raises, naming what was returned."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the cross-pool call to be denied, but it SUCCEEDED and returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _try_scoped_client(ctx, sts, role_arn):
    try:
        assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)
    except ClientError:
        return None
    creds = assumed["Credentials"]
    return ctx.client(
        "cognito-idp",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
