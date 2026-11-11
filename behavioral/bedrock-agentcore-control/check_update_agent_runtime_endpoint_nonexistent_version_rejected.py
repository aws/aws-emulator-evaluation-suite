"""update-agent-runtime-endpoint-nonexistent-version-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-agent-runtime-endpoint-nonexistent-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAgentRuntimeEndpoint to a never-created version is refused with ResourceNotFoundException "Agent with
    agentId: <id> not found", and the endpoint still targets the runtime's real version."""
    control = ctx.client("bedrock-agentcore-control")
    role_arn = _create_runtime_role(ctx)

    create_resp = _create_agent_runtime_with_retry(
        control,
        agentRuntimeName=_no_hyphen_name(ctx, "sim2realagentrt"),
        agentRuntimeArtifact={
            "containerConfiguration": {"containerUri": "public.ecr.aws/lambda/python:3.13"}
        },
        roleArn=role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
        tags={"sim2real": CHECK},
    )
    agent_runtime_id = create_resp["agentRuntimeId"]
    ctx.on_cleanup(lambda: _delete_agent_runtime_best_effort(control, agent_runtime_id))
    real_version = create_resp["agentRuntimeVersion"]

    runtime_state = _poll_until(
        lambda: control.get_agent_runtime(agentRuntimeId=agent_runtime_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )
    assert runtime_state["status"] == "READY", (
        f"expected the agent runtime to reach READY, got {runtime_state['status']!r}"
    )

    endpoint_name = _no_hyphen_name(ctx, "sim2realendpoint")
    endpoint_resp = control.create_agent_runtime_endpoint(
        agentRuntimeId=agent_runtime_id,
        name=endpoint_name,
        agentRuntimeVersion=real_version,
    )
    ctx.on_cleanup(lambda: _delete_endpoint_and_wait(control, agent_runtime_id, endpoint_name))
    assert endpoint_resp["targetVersion"] == real_version, (
        f"expected the new endpoint to target {real_version!r}, "
        f"got {endpoint_resp['targetVersion']!r}"
    )

    # break exactly one thing: retarget the endpoint to a version that was
    # never created for this runtime.
    bogus_version = "88888"
    assert bogus_version != real_version, (
        f"test setup invalid: bogus_version {bogus_version!r} collided with "
        f"the real created version"
    )
    code, message = _error_detail(
        lambda: control.update_agent_runtime_endpoint(
            agentRuntimeId=agent_runtime_id,
            endpointName=endpoint_name,
            agentRuntimeVersion=bogus_version,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"Agent with agentId: {agent_runtime_id} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the endpoint still targets the real version.
    still_there = control.get_agent_runtime_endpoint(
        agentRuntimeId=agent_runtime_id, endpointName=endpoint_name
    )
    assert still_there["targetVersion"] == real_version, (
        f"expected the endpoint to still target {real_version!r} after the "
        f"rejected update, got {still_there['targetVersion']!r}"
    )


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _delete_endpoint_and_wait(control, agent_runtime_id, endpoint_name, timeout_s=600.0, interval_s=5.0):
    """Delete the endpoint once it leaves a transitional status, then wait until it reads as
    not found, so the runtime delete that follows is not refused; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = control.get_agent_runtime_endpoint(
                agentRuntimeId=agent_runtime_id, endpointName=endpoint_name
            )["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if last not in ("CREATING", "UPDATING", "DELETING"):
            try:
                control.delete_agent_runtime_endpoint(
                    agentRuntimeId=agent_runtime_id, endpointName=endpoint_name
                )
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ConflictException", "ValidationException"):
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown: endpoint {endpoint_name} still present after {timeout_s}s ({last})")
        time.sleep(interval_s)


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

