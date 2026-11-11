"""invoke-agent-runtime-missing-permission-denied."""
from __future__ import annotations

import json
import random
import string
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-agent-runtime-missing-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore"]

_SESSION_NAME = "sim2real-behav-session"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeAgentRuntime from a role with no bedrock-agentcore permission is refused with
    AccessDeniedException naming the role, action and runtime ARN, while a fully permitted caller on
    the same nonexistent ARN gets ResourceNotFoundException: the first refusal is the IAM decision.
    """
    account_id = _account_id(ctx)
    runtime_id = f"sim2real-behav-rt-{_rand_suffix(10)}"
    runtime_arn = f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:runtime/{runtime_id}"
    payload = json.dumps({"prompt": "hello"}).encode("utf-8")

    # Restricted principal: allowed to call STS only, no bedrock-agentcore permission at all.
    restricted, role_name = _assume_role_client(
        ctx,
        "bedrock-agentcore",
        [{"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}],
    )

    code, message = _error(
        lambda: restricted.invoke_agent_runtime(agentRuntimeArn=runtime_arn, payload=payload)
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: bedrock-agentcore:InvokeAgentRuntime on resource: {runtime_arn} "
        "because no identity-based policy allows the bedrock-agentcore:InvokeAgentRuntime action"
    ), f"unexpected AccessDeniedException message {message!r}"

    full = ctx.client("bedrock-agentcore")
    control_code, control_message = _error(
        lambda: full.invoke_agent_runtime(agentRuntimeArn=runtime_arn, payload=payload)
    )
    assert control_code == "ResourceNotFoundException", (
        "positive control: a fully-permitted caller invoking the same nonexistent runtime "
        f"ARN should reach resource-lookup logic (ResourceNotFoundException), got {control_code}"
    )
    assert control_message == (
        f"No endpoint or agent found with qualifier 'DEFAULT' for agent '{runtime_arn}'"
    ), (
        f"unexpected ResourceNotFoundException message {control_message!r}"
    )


def _rand_suffix(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. A call that
    succeeds raises AssertionError, so an accepted call never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
                RoleArn=role_arn, RoleSessionName=_SESSION_NAME
            )["Credentials"]
            break
        except ClientError as err:
            last_err = err
            time.sleep(1.5)
    if creds is None:
        raise AssertionError(f"role never became assumable: {last_err}")

    # Re-signed through ctx.client(creds=...), never a bare boto3.client(...), so the
    # second hop keeps THIS target's endpoint -- a hand-rolled client would reach real
    # AWS unconditionally on an emulator run and the check would grade the wrong target.
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
