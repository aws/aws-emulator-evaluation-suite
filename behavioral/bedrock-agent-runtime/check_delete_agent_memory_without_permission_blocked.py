"""delete-agent-memory-without-permission-blocked."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-agent-memory-without-permission-blocked"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAgentMemory by a role without the permission gets AccessDeniedException with the exact
    denial message, while a permitted caller making the same call gets ResourceNotFoundException
    "Agent or Alias not found.", so the denial is authorization."""
    agent_id = "ABCDEFGHIJ"  # matches ^[0-9a-zA-Z]+$, len<=10, never created
    agent_alias_id = "ZYXWVUTSRQ"  # matches ^[0-9a-zA-Z]+$, len<=10

    denied_client, denied_arn = _create_locked_down_client(ctx, "bedrock-agent-runtime")
    _, partition, _, _, account_id, _ = denied_arn.split(":", 5)
    alias_arn = (
        f"arn:{partition}:bedrock:{ctx.region}:{account_id}:agent-alias/{agent_id}/{agent_alias_id}"
    )

    def denied_call():
        denied_client.delete_agent_memory(agentId=agent_id, agentAliasId=agent_alias_id)

    # Freshly-minted STS credentials can draw a transient UnrecognizedClientException for a
    # few seconds while they propagate; poll (bounded) until the settled authorization outcome.
    deadline = time.monotonic() + 30.0
    denied_code = denied_message = None
    while time.monotonic() < deadline:
        denied_code, denied_message = _error(denied_call)
        if denied_code != "UnrecognizedClientException":
            break
        time.sleep(2.0)
    assert denied_code == "AccessDeniedException", denied_code
    expected_denied = (
        f"User: {denied_arn} is not authorized to perform: bedrock:DeleteAgentMemory on "
        f"resource: {alias_arn} because no identity-based policy allows the "
        f"bedrock:DeleteAgentMemory action"
    )
    assert denied_message == expected_denied, (
        f"expected message {expected_denied!r}, got {denied_message!r}"
    )

    allowed_client = ctx.client("bedrock-agent-runtime")

    def allowed_call():
        allowed_client.delete_agent_memory(agentId=agent_id, agentAliasId=agent_alias_id)

    allowed_code, allowed_message = _error(allowed_call)
    assert allowed_code == "ResourceNotFoundException", allowed_code
    assert allowed_message == "Agent or Alias not found.", (
        f"expected message 'Agent or Alias not found.', got {allowed_message!r}"
    )


def _error(fn):
    """Call fn() and return its error (code, message); raise AssertionError if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_locked_down_client(ctx, service: str):
    """Create an IAM role with NO attached policies (implicit deny on everything),
    assume it, and return (client for `service` under those credentials, assumed-role ARN)."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-lockdown-")
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # IAM role trust policies are eventually consistent (documented propagation
    # window of a few to ~10s); poll assume_role rather than sleeping a fixed time.
    deadline = time.monotonic() + 30.0
    creds = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-lockdown")
            creds = assumed["Credentials"]
            assumed_arn = assumed["AssumedRoleUser"]["Arn"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(2.0)
    if creds is None:
        raise AssertionError(f"could not assume locked-down role in time: {last_exc}")

    # ctx.client(..., creds=...) re-signs with the assumed-role credentials while keeping
    # THIS run's endpoint (real AWS or emulator) and TLS settings -- a bare boto3.client()
    # here would hand-roll the endpoint and silently talk to real AWS even on an emulator run.
    client = ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, assumed_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
