"""update-agent-runtime-invalid-state-transition-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-agent-runtime-invalid-state-transition-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAgentRuntime on a runtime that has just been put into DELETING is
    rejected with ConflictException rather than racing the delete, and
    updating a live READY runtime still succeeds (positive control)."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_role(ctx)
    container_uri = "public.ecr.aws/lambda/python:3.12"

    name1 = _alnum(ctx, "s2rArt", 48)
    created = _create_agent_runtime_with_role_retry(
        bac,
        agentRuntimeName=name1,
        agentRuntimeArtifact={"containerConfiguration": {"containerUri": container_uri}},
        roleArn=role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
    )
    runtime_id = created["agentRuntimeId"]
    ctx.on_cleanup(lambda: _delete_runtime_and_wait(bac, runtime_id, ctx.account))
    ready = _poll(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=300.0,
    )
    assert ready["status"] == "READY", f"expected the runtime to settle at READY, got {ready['status']!r}"
    runtime_arn = ready["agentRuntimeArn"]

    # The check holds the DELETING window itself: it starts the delete and issues
    # the update straight away. The window lasts a few seconds, and the refusal
    # message names the DELETING state, so a pass proves the update hit it.
    delete_resp = bac.delete_agent_runtime(agentRuntimeId=runtime_id)
    assert delete_resp["status"] == "DELETING", "sanity: delete should immediately mark DELETING"
    code, message = _error_detail(
        lambda: bac.update_agent_runtime(
            agentRuntimeId=runtime_id,
            agentRuntimeArtifact={"containerConfiguration": {"containerUri": container_uri}},
            roleArn=role_arn,
            networkConfiguration={"networkMode": "PUBLIC"},
            description="attempted update mid-delete",
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}: {message!r}"
    expected_message = (
        f"Cannot update agent {runtime_arn} while it's DELETING. Please try again when the agent is ready."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected update does not pull the runtime back out of the
    # delete; the delete runs to completion and the runtime reads as not found.
    gone_code, gone_message = _poll_gone(lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id))
    assert gone_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {gone_code!r}"
    expected_gone = f"Agent with agentId: {runtime_id}, accountId: {ctx.account}, and version: null not found!"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"

    # Positive control: updating a live READY runtime succeeds.
    name2 = _alnum(ctx, "s2rArt2", 48)
    created2 = _create_agent_runtime_with_role_retry(
        bac,
        agentRuntimeName=name2,
        agentRuntimeArtifact={"containerConfiguration": {"containerUri": container_uri}},
        roleArn=role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
    )
    runtime_id2 = created2["agentRuntimeId"]
    ctx.on_cleanup(lambda: _delete_runtime_and_wait(bac, runtime_id2, ctx.account))
    ready2 = _poll(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id2),
        lambda r: r["status"] != "CREATING",
        timeout_s=300.0,
    )
    assert ready2["status"] == "READY", f"expected the runtime to settle at READY, got {ready2['status']!r}"

    updated = bac.update_agent_runtime(
        agentRuntimeId=runtime_id2,
        agentRuntimeArtifact={"containerConfiguration": {"containerUri": container_uri}},
        roleArn=role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
        description="normal update",
    )
    assert updated["status"] in ("UPDATING", "READY"), f"unexpected status from update response: {updated['status']!r}"

    # Terminal read: independent of the mutating call, at the destination.
    after2 = _poll(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id2),
        lambda r: r["status"] != "UPDATING",
        timeout_s=300.0,
    )
    assert after2["status"] == "READY", f"positive-control update did not settle READY: {after2['status']!r}"
    assert int(after2["agentRuntimeVersion"]) > int(created2["agentRuntimeVersion"]), (
        f"expected version to advance past {created2['agentRuntimeVersion']!r}, got {after2['agentRuntimeVersion']!r}"
    )


def _alnum(ctx, prefix: str, maxlen: int) -> str:
    raw = ctx.unique_name(prefix)
    name = re.sub(r"[^A-Za-z0-9_]", "", raw)
    return name[:maxlen]


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_gone(read, timeout_s=300.0, interval_s=2.0):
    """Poll read() until it raises ClientError; return (code, message). Raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = read()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"resource still readable after {timeout_s}s; last value={last!r}")


def _delete_runtime_and_wait(bac, runtime_id, account, timeout_s=300.0):
    """Delete the runtime unless it is already gone, then wait until it reads as not found."""
    try:
        bac.get_agent_runtime(agentRuntimeId=runtime_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    try:
        bac.delete_agent_runtime(agentRuntimeId=runtime_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise
    code, message = _poll_gone(lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id), timeout_s=timeout_s)
    gone = f"Agent with agentId: {runtime_id}, accountId: {account}, and version: null not found!"
    if (code, message) != ("ResourceNotFoundException", gone):
        raise AssertionError(
            f"teardown: runtime {runtime_id} read failed with {code} {message!r} instead of not-found"
        )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_agentcore_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = _alnum(ctx, "s2rBacRole", 64)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_agent_runtime_with_role_retry(bac, timeout_s=120.0, interval_s=5.0, **kwargs):
    """CreateAgentRuntime validates the execution role's trust policy synchronously; a role
    created moments ago can still fail that check while IAM propagates it. Retry on that
    specific ValidationException instead of treating it as a hard failure."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return bac.create_agent_runtime(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "Role validation failed" in msg:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
