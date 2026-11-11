"""assume-role-session-name-unicode-preserved-in-arn."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-session-name-unicode-preserved-in-arn"
GROUP = "representation"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A RoleSessionName using every allowed special character (``^[\\w+=,.@-]*$``) is echoed
    exactly in AssumedRoleUser.Arn and AssumedRoleId, and GetCallerIdentity through the
    session reports the same ARN."""
    sts = ctx.client("sts")
    role_name, role_arn = _create_assumable_role(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}],
        },
    )
    _warm_up_assume_role(ctx, role_arn)

    suffix = uuid.uuid4().hex[:8]
    session_name = f"sim2real+Test=Name,With.Special@Chars-{suffix}"
    assert 2 <= len(session_name) <= 64, (
        f"test bug: constructed session_name length {len(session_name)} outside [2, 64]"
    )

    resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    assumed_arn = resp["AssumedRoleUser"]["Arn"]
    assumed_id = resp["AssumedRoleUser"]["AssumedRoleId"]
    assert assumed_arn.endswith(f"/{session_name}"), (
        f"expected AssumedRoleUser.Arn to end with /{session_name}, got {assumed_arn}"
    )
    assert assumed_id.endswith(f":{session_name}"), (
        f"expected AssumedRoleUser.AssumedRoleId to end with :{session_name}, got {assumed_id}"
    )

    identity = _client_with_creds(ctx, "sts", resp["Credentials"]).get_caller_identity()
    assert identity["Arn"] == assumed_arn, (
        f"expected GetCallerIdentity through the assumed session to report {assumed_arn}, "
        f"got {identity['Arn']}"
    )


def _tags_kv():
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _create_assumable_role(ctx, identity_policy_document):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="perm", PolicyDocument=json.dumps(identity_policy_document)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="perm"))
    return role_name, role_arn


def _warm_up_assume_role(ctx, role_arn: str, timeout_s: float = 45.0, interval_s: float = 3.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="warmup")["Credentials"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"role never became assumable within {timeout_s}s: {last_exc}")


def _client_with_creds(ctx, service: str, creds: dict):
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
