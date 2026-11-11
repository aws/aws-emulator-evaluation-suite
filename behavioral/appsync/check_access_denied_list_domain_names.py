"""access-denied-list-domain-names."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-denied-list-domain-names"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal with an explicit IAM Deny on appsync:ListDomainNames is rejected with
    AccessDeniedException while the unrestricted principal lists normally, and removing the
    deny restores the call for the same principal."""
    restricted, remove_deny, session_arn = _create_denied_appsync_client(
        ctx, ["appsync:ListDomainNames"]
    )
    account_id = session_arn.split(":")[4]
    expected = (
        "AccessDeniedException",
        f"User: {session_arn} is not authorized to perform: appsync:ListDomainNames on resource: "
        f"arn:aws:appsync:{ctx.region}:{account_id}:* "
        "with an explicit deny in an identity-based policy",
    )

    denied = _poll_until(
        lambda: _error(lambda: restricted.list_domain_names()),
        lambda seen: seen == expected,
        timeout_s=60,
        interval_s=5,
        description="the explicit deny on ListDomainNames is enforced",
    )
    assert denied == expected, f"expected {expected}, got {denied}"

    admin = ctx.client("appsync")
    resp = admin.list_domain_names()
    assert "domainNameConfigs" in resp, f"expected domainNameConfigs in response, got {resp!r}"

    remove_deny()
    restored = _poll_until(
        lambda: _list_or_code(restricted),
        lambda r: isinstance(r, dict),
        timeout_s=180,
        interval_s=5,
        description="the restricted principal's ListDomainNames succeeds after the deny is removed",
    )
    assert "domainNameConfigs" in restored, (
        f"expected the restricted principal to succeed once the deny statement is removed, "
        f"got {restored}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _list_or_code(client):
    """ListDomainNames response on success, or the error code while the deny is still in force."""
    try:
        return client.list_domain_names()
    except ClientError as e:
        return e.response.get("Error", {}).get("Code")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_denied_appsync_client(ctx, deny_actions):
    """Create an IAM role that can be assumed by the caller's own account but
    that explicitly denies `deny_actions`, then assume it and return an appsync
    client on the same target using those restricted credentials, a `remove_deny`
    callback that rewrites the role's policy to drop the deny statement (used to
    prove the denial restores, not just occurs), and the assumed-role session ARN."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-appsync-deny-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "deny-policy"
    allow_only_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "appsync:*", "Resource": "*"}],
    }
    deny_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "appsync:*", "Resource": "*"},
            {"Effect": "Deny", "Action": deny_actions, "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(deny_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    def remove_deny():
        iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(allow_only_doc)
        )

    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")
            creds = assumed["Credentials"]
            client = ctx.client("appsync", creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            })
            return client, remove_deny, assumed["AssumedRoleUser"]["Arn"]
        except ClientError as e:
            last_err = e
            time.sleep(2)
    raise AssertionError(f"could not assume restricted role in time: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
