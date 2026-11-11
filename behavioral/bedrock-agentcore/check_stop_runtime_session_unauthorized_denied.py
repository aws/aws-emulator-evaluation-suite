"""stop-runtime-session-unauthorized-denied."""
from __future__ import annotations

import json
import random
import string
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-runtime-session-unauthorized-denied"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopRuntimeSession from a role without bedrock-agentcore:StopRuntimeSession is refused with
    AccessDeniedException naming the role, action and runtime ARN, while a fully permitted caller on
    the same nonexistent session gets ResourceNotFoundException: the refusal is the IAM decision.
    """
    account_id = _account_id(ctx)
    runtime_id = f"sim2real-behav-rt-{_rand_suffix(10)}"
    runtime_arn = f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:runtime/{runtime_id}"
    # SessionType requires length 33-256; build a clearly synthetic, sufficiently long id.
    session_id = f"sim2real-behav-session-{_rand_suffix(24)}"

    restricted, role_name = _assume_role_client(
        ctx,
        "bedrock-agentcore",
        [{"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}],
    )

    code, message = _error(
        lambda: _settled(
            lambda: restricted.stop_runtime_session(
                runtimeSessionId=session_id, agentRuntimeArn=runtime_arn
            )
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-behav-session is not "
        f"authorized to perform: bedrock-agentcore:StopRuntimeSession on resource: {runtime_arn} "
        "because no identity-based policy allows the bedrock-agentcore:StopRuntimeSession action"
    ), f"expected the exact identity-policy denial message, got {message!r}"

    full = ctx.client("bedrock-agentcore")
    control_code, control_message = _error(
        lambda: full.stop_runtime_session(
            runtimeSessionId=session_id, agentRuntimeArn=runtime_arn
        )
    )
    assert control_code == "ResourceNotFoundException", (
        "positive control: a fully-permitted caller stopping the same nonexistent session "
        f"should reach resource-lookup logic (ResourceNotFoundException), got {control_code}"
    )
    assert control_message == (
        f"No endpoint or agent found with qualifier 'DEFAULT' for agent '{runtime_arn}'"
    ), f"expected the exact runtime-not-found message, got {control_message!r}"


def _rand_suffix(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


# A session token AssumeRole just minted can be refused by the service for a few seconds.
_TOKEN_NOT_YET_VALID = "The security token included in the request is invalid."


def _settled(fn, *, timeout_s=60.0, interval_s=3.0):
    """fn() once the service accepts the freshly minted session token. Only that refusal is
    retried, within a bounded window; any other outcome, and the last refusal, is returned or
    raised as is."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"].get("Message") != _TOKEN_NOT_YET_VALID:
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _assume_role_client(ctx, service: str, statements: list[dict[str, Any]]):
    """Create an IAM role whose inline policy is exactly `statements`, assume it, and return a
    client for `service` backed by the resulting temporary credentials, and the role name."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = _account_id(ctx)
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = "inline-scope"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )

    deadline = time.monotonic() + 30.0
    creds = None
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-behav-session"
            )["Credentials"]
            break
        except ClientError as err:
            last_err = err
            time.sleep(1.5)
    if creds is None:
        raise AssertionError(f"role never became assumable: {last_err}")

    client = ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, role_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
