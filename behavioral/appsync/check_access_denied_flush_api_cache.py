"""access-denied-flush-api-cache."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-denied-flush-api-cache"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal with an explicit IAM Deny on appsync:FlushApiCache for the API is rejected with
    AccessDeniedException, while the unrestricted principal's identical call fails on resource
    state (no cache), so the denial comes from IAM."""
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real-behav": "access-denied-flush-api-cache"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    restricted, session_arn = _create_denied_appsync_client(ctx, ["appsync:FlushApiCache"])
    account_id = session_arn.split(":")[4]
    expected = (
        f"User: {session_arn} is not authorized to perform: appsync:FlushApiCache on resource: "
        f"arn:aws:appsync:{ctx.region}:{account_id}:/v1/apis/{api_id}/FlushCache "
        "with an explicit deny in an identity-based policy"
    )

    # IAM policy evaluation for a freshly-created role can lag briefly behind the
    # role/policy creation; poll until the explicit deny is enforced (or a generous
    # deadline elapses) instead of asserting on the first try.
    deadline = time.monotonic() + 60
    code = message = None
    while time.monotonic() < deadline:
        code, message = _error(lambda: restricted.flush_api_cache(apiId=api_id))
        if code == "AccessDeniedException" and message == expected:
            break
        time.sleep(5)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    control_code, control_message = _error(lambda: appsync.flush_api_cache(apiId=api_id))
    assert control_code == "NotFoundException", (
        f"expected the unrestricted principal to fail because no cache exists "
        f"for the API (NotFoundException), got {control_code}"
    )
    assert control_message == (
        "Unable to flush the cache as it doesn't exist, please create the cache first."
    ), control_message


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _create_denied_appsync_client(ctx, deny_actions):
    """Create an IAM role that can be assumed by the caller's own account but
    that explicitly denies `deny_actions`, then assume it and return an appsync
    client on the same target using those restricted credentials, plus the
    assumed-role session ARN."""
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
        Tags=[{"Key": "sim2real-behav", "Value": "access-denied-flush-api-cache"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "deny-policy"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "appsync:*", "Resource": "*"},
            {"Effect": "Deny", "Action": deny_actions, "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

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
            return client, assumed["AssumedRoleUser"]["Arn"]
        except ClientError as e:
            last_err = e
            time.sleep(2)
    raise AssertionError(f"could not assume restricted role in time: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
