"""get-ui-customization-cross-pool-access-denied-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-ui-customization-cross-pool-access-denied-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetUICustomization from a principal whose policy grants only another pool's ARN is
    rejected with AccessDeniedException, while the same principal succeeds on the pool it is
    scoped to."""
    cip_root = ctx.client("cognito-idp")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    target_pool = _create_pool(ctx)
    decoy_pool = _create_pool(ctx)
    target_arn = cip_root.describe_user_pool(UserPoolId=target_pool)["UserPool"]["Arn"]
    decoy_arn = cip_root.describe_user_pool(UserPoolId=decoy_pool)["UserPool"]["Arn"]

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-cog-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_json(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    scoped_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "cognito-idp:GetUICustomization",
                "Resource": decoy_arn,
            }
        ],
    }
    policy_name = "scoped-to-decoy-pool"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=_json(scoped_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    session_name = "sim2real-session"
    restricted_cip = _assume_role_client(ctx, sts, role_arn, session_name)

    code, message = _error(lambda: restricted_cip.get_ui_customization(UserPoolId=target_pool))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    caller_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"
    expected = (
        f"User: {caller_arn} is not authorized to perform: cognito-idp:GetUICustomization on "
        f"resource: {target_arn} because no identity-based policy allows the "
        "cognito-idp:GetUICustomization action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


    # positive control: the same restricted principal succeeds against the
    # pool its policy actually scopes it to (GetUICustomization requires the
    # pool to have a domain configured before it will return real data)
    domain = ctx.unique_name("sim2real-cog-domain-").replace("_", "-").lower()
    cip_root.create_user_pool_domain(Domain=domain, UserPoolId=decoy_pool)
    ctx.on_cleanup(lambda: cip_root.delete_user_pool_domain(Domain=domain, UserPoolId=decoy_pool))
    _wait_for_domain_active(cip_root, domain)

    resp = restricted_cip.get_ui_customization(UserPoolId=decoy_pool)
    assert "UICustomization" in resp, (
        f"expected the scoped principal's granted-pool call to return UICustomization data, "
        f"got {resp!r}"
    )


def _json(obj):
    import json
    return json.dumps(obj)


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _create_pool(ctx):
    cip = ctx.client("cognito-idp")
    pool_id = cip.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cog-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cog"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cip.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _wait_for_domain_active(cip, domain, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        desc = cip.describe_user_pool_domain(Domain=domain).get("DomainDescription") or {}
        last_status = desc.get("Status")
        if last_status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"domain {domain} did not become ACTIVE within {timeout_s}s (last={last_status})")



def _assume_role_client(ctx, sts, role_arn, session_name, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            return ctx.client(
                "cognito-idp",
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as err:
            last_err = err
            time.sleep(2)
    raise AssertionError(f"could not assume role within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
