"""assume-role-session-tags-unicode-value-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-session-tags-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["sts"]
# What an error-code helper returns when the call succeeds: equal to no AWS error code.
_OK = "(no error: the call succeeded)"


@tags("axis:happy-path", "cap:c7", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A unicode session tag value is preserved exactly in aws:PrincipalTag: an exact-match role
    condition denies the session with no tag or a diacritics-stripped value, and allows the
    exact unicode value."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    user_name = ctx.unique_name("sim2real-behav-tagrt-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    user_arn = f"arn:aws:iam::{account_id}:user/{user_name}"

    role_name = ctx.unique_name("sim2real-behav-tagrt-role-")
    tag_value = "Café-Zürich-北京"
    role_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAssume",
                "Effect": "Allow",
                "Principal": {"AWS": user_arn},
                "Action": "sts:AssumeRole",
            },
            {
                "Sid": "AllowTagSession",
                "Effect": "Allow",
                "Principal": {"AWS": user_arn},
                "Action": "sts:TagSession",
            },
        ],
    }
    role_arn = _create_role_with_new_principal(
        iam, role_name, json.dumps(role_trust)
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    role_policy_name = "sim2real-behav-tagrt-policy"
    role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:ListRoles",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalTag/Team": tag_value}},
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=role_policy_name,
        PolicyDocument=json.dumps(role_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=role_policy_name)
    )

    user_policy_name = "sim2real-behav-tagrt-user-policy"
    user_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}],
    }
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=user_policy_name,
        PolicyDocument=json.dumps(user_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_user_policy(UserName=user_name, PolicyName=user_policy_name)
    )

    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(
            UserName=user_name, AccessKeyId=access_key["AccessKeyId"]
        )
    )
    user_creds = {
        "AccessKeyId": access_key["AccessKeyId"],
        "SecretAccessKey": access_key["SecretAccessKey"],
    }
    base_client = _client_with_creds(ctx, "sts", user_creds)
    _wait_for_new_credentials(base_client)

    # Without the matching principal tag, the condition never holds -> implicit deny.
    no_tag_creds = _wait_for_assume_role(
        base_client, RoleArn=role_arn, RoleSessionName="no-tag-session"
    )
    no_tag_iam = _client_with_creds(ctx, "iam", no_tag_creds)
    code, message = _error(lambda: no_tag_iam.list_roles())
    assert code == "AccessDenied", code
    assert message == _list_roles_denied_message(account_id, role_name, "no-tag-session"), message

    # A value differing only by stripped diacritics must fail: this separates value fidelity
    # from mere key presence.
    wrong_tag_value = "Cafe-Zurich-北京"
    assert wrong_tag_value != tag_value, (wrong_tag_value, tag_value)
    mismatched_creds = _wait_for_assume_role(
        base_client,
        RoleArn=role_arn,
        RoleSessionName="mismatched-tag-session",
        Tags=[{"Key": "Team", "Value": wrong_tag_value}],
    )
    mismatched_iam = _client_with_creds(ctx, "iam", mismatched_creds)
    code, message = _error(lambda: mismatched_iam.list_roles())
    assert code == "AccessDenied", code
    assert message == _list_roles_denied_message(
        account_id, role_name, "mismatched-tag-session"
    ), message

    # With the exact unicode tag value, the condition holds -> allowed.
    tagged_creds = _wait_for_assume_role(
        base_client,
        RoleArn=role_arn,
        RoleSessionName="tagged-session",
        Tags=[{"Key": "Team", "Value": tag_value}],
    )
    tagged_iam = _client_with_creds(ctx, "iam", tagged_creds)
    result = tagged_iam.list_roles()
    role_names = [r["RoleName"] for r in result["Roles"]]
    assert role_name in role_names, (role_name, role_names)


def _create_role_with_new_principal(
    iam_client, role_name: str, trust_policy_json: str, timeout_s: float = 20.0, interval_s: float = 2.0
) -> str:
    """CreateRole retried through MalformedPolicyDocument ("Invalid principal in policy"),
    which IAM returns while a just-created principal propagates."""
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return iam_client.create_role(
                RoleName=role_name, AssumeRolePolicyDocument=trust_policy_json
            )["Role"]["Arn"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "MalformedPolicyDocument":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"create_role never accepted the new principal within {timeout_s}s: {last_err}")


def _client_with_creds(ctx, service: str, creds: dict[str, Any]):
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds.get("SessionToken"),
    })


def _wait_for_new_credentials(sts_client, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            sts_client.get_caller_identity()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("InvalidClientTokenId", "AccessDenied"):
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"new access key never became active within {timeout_s}s: {last_err}")


def _wait_for_assume_role(sts_client, timeout_s: float = 30.0, interval_s: float = 2.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return sts_client.assume_role(**kwargs)["Credentials"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "AccessDenied":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"assume_role never became permitted within {timeout_s}s: {last_err}")


def _error(fn):
    """``(code, message)`` of the refusal ``fn()`` raises; raises if the call succeeds."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _list_roles_denied_message(account_id: str, role_name: str, session_name: str) -> str:
    return (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: iam:ListRoles on resource: arn:aws:iam::{account_id}:role/ "
        "because no identity-based policy allows the iam:ListRoles action"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
