"""agent-runtime-create-returns-creating-status."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agent-runtime-create-returns-creating-status"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAgentRuntime answers status CREATING and agentRuntimeVersion "1" with an ARN ending in the runtime id;
    GetAgentRuntime then reports the runtime READY with the same ARN and version "1"."""
    control = ctx.client("bedrock-agentcore-control")
    role_arn = _create_runtime_role(ctx)

    name = _no_hyphen_name(ctx, "sim2realagentrt")
    create_resp = _create_agent_runtime_with_retry(
        control,
        agentRuntimeName=name,
        agentRuntimeArtifact={
            "containerConfiguration": {"containerUri": "public.ecr.aws/lambda/python:3.13"}
        },
        roleArn=role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
        tags={"sim2real:managed": "true", "sim2real:check": CHECK},
    )
    agent_runtime_id = create_resp["agentRuntimeId"]
    ctx.on_cleanup(lambda: _delete_agent_runtime_best_effort(control, agent_runtime_id))

    assert create_resp["status"] == "CREATING", (
        f"expected synchronous CreateAgentRuntime response status CREATING, "
        f"got {create_resp['status']!r}"
    )
    assert create_resp["agentRuntimeVersion"] == "1", (
        f"expected agentRuntimeVersion '1' for a brand-new runtime, "
        f"got {create_resp['agentRuntimeVersion']!r}"
    )
    assert create_resp["agentRuntimeArn"].endswith(agent_runtime_id), (
        f"expected agentRuntimeArn {create_resp['agentRuntimeArn']!r} to end with "
        f"agentRuntimeId {agent_runtime_id!r}"
    )

    # Terminal assertion is an independent read (GetAgentRuntime), not the mutating
    # call's own response, polled until provisioning leaves CREATING.
    get_resp = _poll_until(
        lambda: control.get_agent_runtime(agentRuntimeId=agent_runtime_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert get_resp["status"] == "READY", (
        f"expected the runtime to settle at READY, got {get_resp['status']!r} "
        f"(failureReason={get_resp.get('failureReason')!r})"
    )
    assert get_resp["agentRuntimeArn"] == create_resp["agentRuntimeArn"], (
        f"independent read returned agentRuntimeArn {get_resp['agentRuntimeArn']!r}, "
        f"expected it to match the create response's {create_resp['agentRuntimeArn']!r}"
    )
    assert get_resp["agentRuntimeVersion"] == "1", (
        f"independent read expected agentRuntimeVersion '1', got "
        f"{get_resp['agentRuntimeVersion']!r}"
    )


def _poll_until(probe, predicate, timeout_s=600.0, interval_s=10.0):
    """Call probe() until predicate holds; raise AssertionError on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _no_hyphen_name(ctx, prefix):
    raw = ctx.unique_name(f"{prefix}-")
    sanitized = "".join(ch for ch in raw if ch.isalnum() or ch == "_")
    return sanitized[:40]


def _create_runtime_role(ctx):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-agentcore-rt-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeRolePolicy",
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _delete_agent_runtime_best_effort(control, agent_runtime_id):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            control.delete_agent_runtime(agentRuntimeId=agent_runtime_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException":
                raise
            time.sleep(5)
    # last attempt - let any remaining error surface rather than leak silently.
    control.delete_agent_runtime(agentRuntimeId=agent_runtime_id)


def _create_agent_runtime_with_retry(control, *, timeout_s=120.0, interval_s=8.0, **kwargs):
    """IAM role propagation is eventually consistent; retry past a transient
    'Role validation failed' ValidationException instead of treating it as a
    permanent rejection."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return control.create_agent_runtime(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "Role validation failed" in message and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
