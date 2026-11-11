"""agent-runtime-endpoint-version-pinning."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agent-runtime-endpoint-version-pinning"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAgentRuntimeEndpoint pinned to the runtime's READY version "1" echoes it as targetVersion, and a read
    returns the same targetVersion and runtime ARN; a version that was never created is refused with
    ResourceNotFoundException "Agent with agentId: <id> not found"."""
    control = ctx.client("bedrock-agentcore-control")
    role_arn = _create_runtime_role(ctx)

    runtime_name = _no_hyphen_name(ctx, "sim2realagentrt")
    create_resp = _create_agent_runtime_with_retry(
        control,
        agentRuntimeName=runtime_name,
        agentRuntimeArtifact={
            "containerConfiguration": {"containerUri": "public.ecr.aws/lambda/python:3.13"}
        },
        roleArn=role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2realagentrt"},
    )
    agent_runtime_id = create_resp["agentRuntimeId"]
    ctx.on_cleanup(lambda: _delete_agent_runtime_best_effort(control, agent_runtime_id))
    real_version = create_resp["agentRuntimeVersion"]
    assert real_version == "1", (
        f"expected a freshly created agent runtime to start at version '1', got {real_version!r}"
    )

    # CreateAgentRuntimeEndpoint rejects a version that is still CREATING
    # ("Agent version 1 must be in READY status") — wait for the version to
    # go live before pinning an endpoint to it.
    runtime_state = _poll_until(
        lambda: control.get_agent_runtime(agentRuntimeId=agent_runtime_id),
        lambda r: r["status"] != "CREATING",
    )
    assert runtime_state["status"] == "READY", (
        f"expected the agent runtime to settle into READY, got {runtime_state['status']!r}"
    )

    # positive: pin an endpoint to the real, just-created version.
    endpoint_name = _no_hyphen_name(ctx, "sim2realendpoint")
    endpoint_resp = control.create_agent_runtime_endpoint(
        agentRuntimeId=agent_runtime_id,
        name=endpoint_name,
        agentRuntimeVersion=real_version,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2realendpoint"},
    )
    ctx.on_cleanup(lambda: _delete_endpoint_and_wait(control, agent_runtime_id, endpoint_name))
    assert endpoint_resp["targetVersion"] == real_version, (
        f"expected the endpoint to pin targetVersion={real_version!r}, got "
        f"{endpoint_resp['targetVersion']!r}"
    )
    assert endpoint_resp["status"] in ("CREATING", "READY"), (
        f"expected a freshly created endpoint to be CREATING or READY, got {endpoint_resp['status']!r}"
    )

    fetched = control.get_agent_runtime_endpoint(
        agentRuntimeId=agent_runtime_id, endpointName=endpoint_name
    )
    assert fetched["targetVersion"] == real_version, (
        f"independent read: expected targetVersion={real_version!r}, got {fetched['targetVersion']!r}"
    )
    assert fetched["agentRuntimeArn"] == create_resp["agentRuntimeArn"], (
        f"independent read: expected agentRuntimeArn={create_resp['agentRuntimeArn']!r}, got "
        f"{fetched['agentRuntimeArn']!r}"
    )

    # negative / overly-permissive boundary: a version that was never created
    # for this runtime must be rejected, not silently accepted.
    bogus_version = "99999"
    assert bogus_version != real_version, (
        f"test setup invariant broken: bogus_version {bogus_version!r} collided with real_version"
    )
    code, message = _error(
        lambda: control.create_agent_runtime_endpoint(
            agentRuntimeId=agent_runtime_id,
            name=_no_hyphen_name(ctx, "sim2realendpointbad"),
            agentRuntimeVersion=bogus_version,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected the nonexistent version to be rejected with ResourceNotFoundException, "
        f"got code={code!r}"
    )
    expected = f"Agent with agentId: {agent_runtime_id} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _no_hyphen_name(ctx, prefix):
    raw = ctx.unique_name(f"{prefix}-")
    sanitized = "".join(ch for ch in raw if ch.isalnum() or ch == "_")
    return sanitized[:40]


def _create_runtime_role(ctx):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    role_name = ctx.unique_name("sim2real-agentcore-rt-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeRolePolicy",
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:bedrock-agentcore:{region}:{account_id}:*"
                    },
                },
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-agentcore-rt-role"},
        ],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _error(fn):
    """Return (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_endpoint_and_wait(control, agent_runtime_id, endpoint_name, timeout_s=600.0):
    """DeleteAgentRuntimeEndpoint is refused (ConflictException) while the endpoint is still
    CREATING, and an accepted delete completes asynchronously; DeleteAgentRuntime is refused
    until the endpoint is gone, so wait for ResourceNotFoundException and raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            control.delete_agent_runtime_endpoint(
                agentRuntimeId=agent_runtime_id, endpointName=endpoint_name
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"teardown: endpoint {endpoint_name} still present after {timeout_s}s"
            )
        time.sleep(5)


def _delete_agent_runtime_best_effort(control, agent_runtime_id):
    deadline = time.monotonic() + 600
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
    control.delete_agent_runtime(agentRuntimeId=agent_runtime_id)


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


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

