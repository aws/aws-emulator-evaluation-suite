"""invoke-agent-runtime-cross-tenant-denied."""
from __future__ import annotations

import json
import random
import string
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-agent-runtime-cross-tenant-denied"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A principal granted InvokeAgentRuntime on one runtime ARN is refused with
    AccessDeniedException on an unrelated runtime ARN, while on its own ARN it reaches the lookup
    (ResourceNotFoundException): the grant is enforced per resource.
    """
    account_id = _account_id(ctx)
    owned_id = f"sim2real-behav-rt-{_rand_suffix(10)}"
    other_id = f"sim2real-behav-rt-{_rand_suffix(10)}"
    owned_arn = f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:runtime/{owned_id}"
    other_arn = f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:runtime/{other_id}"
    # InvokeAgentRuntime authorizes against BOTH the runtime resource type AND the
    # runtime-endpoint resource type (the default-qualifier invocation resolves to an
    # implicit runtime-endpoint ARN under the runtime), so the grant must cover both.
    owned_endpoint_wildcard = (
        f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:"
        f"runtime/{owned_id}/runtime-endpoint/*"
    )
    payload = json.dumps({"prompt": "hello"}).encode("utf-8")

    restricted, role_name = _assume_role_client(
        ctx,
        "bedrock-agentcore",
        [
            {
                "Effect": "Allow",
                "Action": "bedrock-agentcore:InvokeAgentRuntime",
                "Resource": [owned_arn, owned_endpoint_wildcard],
            }
        ],
    )

    code, message = _error_after_propagation(
        lambda: restricted.invoke_agent_runtime(agentRuntimeArn=other_arn, payload=payload)
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-behav-session "
        f"is not authorized to perform: bedrock-agentcore:InvokeAgentRuntime on resource: {other_arn} "
        "because no identity-based policy allows the bedrock-agentcore:InvokeAgentRuntime action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    control_code, control_message = _error_after_propagation(
        lambda: restricted.invoke_agent_runtime(agentRuntimeArn=owned_arn, payload=payload)
    )
    assert control_code == "ResourceNotFoundException", (
        "positive control: invoking the principal's own permitted (but nonexistent) runtime "
        f"ARN should reach resource-lookup logic, got {control_code}"
    )
    expected_control = f"No endpoint or agent found with qualifier 'DEFAULT' for agent '{owned_arn}'"
    assert control_message == expected_control, (
        f"expected message {expected_control!r}, got {control_message!r}"
    )


def _rand_suffix(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _error(fn):
    """The (code, message) of the ClientError fn raises. An unexpected SUCCESS raises, so a
    target that lets the restricted principal through fails naming what it returned."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


# A just-assumed role's session is refused with this message until IAM propagates it; it says
# nothing about the authorization decision under test.
_UNPROPAGATED = "The security token included in the request is invalid."


def _error_after_propagation(fn, *, timeout_s=60.0, interval_s=3.0):
    """Like _error, but retries while the refusal is the not-yet-propagated session token."""
    deadline = time.monotonic() + timeout_s
    while True:
        code, message = _error(fn)
        if message != _UNPROPAGATED or time.monotonic() >= deadline:
            return code, message
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
    client for `service` backed by the resulting temporary credentials, with the role's name."""
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
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

    # Re-signed through ctx.client(creds=...) so the second hop keeps THIS target's
    # endpoint -- a hand-rolled boto3.client() here would reach real AWS on an
    # emulator run and the check would grade the wrong target.
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
