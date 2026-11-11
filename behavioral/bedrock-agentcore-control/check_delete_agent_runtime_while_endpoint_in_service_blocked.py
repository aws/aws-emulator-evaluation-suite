"""delete-agent-runtime-while-endpoint-in-service-blocked."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-agent-runtime-while-endpoint-in-service-blocked"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAgentRuntime is rejected with ConflictException while a READY endpoint points at
    it, and a runtime with no endpoint is accepted as DELETING, reads DELETING or gone, and ends
    ResourceNotFoundException with the exact not-found message."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_role(ctx)

    container_uri = "public.ecr.aws/lambda/python:3.12"

    # Runtime under test: will get a live endpoint attached.
    name1 = _alnum(ctx, "s2rArt", 48)
    resp1 = _create_agent_runtime_with_role_retry(
        bac,
        agentRuntimeName=name1,
        agentRuntimeArtifact={"containerConfiguration": {"containerUri": container_uri}},
        roleArn=role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
        tags={"sim2real": CHECK},
    )
    runtime_id = resp1["agentRuntimeId"]
    ctx.on_cleanup(lambda: _delete_runtime_and_wait(bac, runtime_id, ctx.account))
    _poll(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=180.0,
    )

    ep_name = _alnum(ctx, "s2rEp", 48)
    bac.create_agent_runtime_endpoint(agentRuntimeId=runtime_id, name=ep_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(
        lambda: _safe(
            lambda: bac.delete_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=ep_name)
        )
    )

    # Let the endpoint leave its transient CREATING state before testing the conflict.
    endpoint = _poll(
        lambda: bac.get_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=ep_name),
        lambda r: r["status"] != "CREATING",
        timeout_s=180.0,
    )
    assert endpoint["status"] == "READY", f"expected the endpoint to settle at READY, got {endpoint['status']!r}"

    code, message = _error_detail(lambda: bac.delete_agent_runtime(agentRuntimeId=runtime_id))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = "This agent has endpoints that must be deleted before the agent can be removed."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the runtime is not being torn down underneath the endpoint.
    still = bac.get_agent_runtime(agentRuntimeId=runtime_id)
    assert still["status"] != "DELETING", "runtime entered DELETING despite the blocked call"

    # Positive control: a runtime with no endpoints deletes cleanly.
    name2 = _alnum(ctx, "s2rArt2", 48)
    resp2 = _create_agent_runtime_with_role_retry(
        bac,
        agentRuntimeName=name2,
        agentRuntimeArtifact={"containerConfiguration": {"containerUri": container_uri}},
        roleArn=role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
        tags={"sim2real": CHECK},
    )
    runtime_id2 = resp2["agentRuntimeId"]
    ctx.on_cleanup(lambda: _delete_runtime_and_wait(bac, runtime_id2, ctx.account))
    _poll(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id2),
        lambda r: r["status"] != "CREATING",
        timeout_s=180.0,
    )
    del_resp = bac.delete_agent_runtime(agentRuntimeId=runtime_id2)
    assert del_resp["status"] == "DELETING", "expected the unreferenced runtime delete to be accepted"

    # Independent read confirms the acceptance, rather than trusting the mutating call's own
    # response: the runtime reads DELETING, or is already gone (no deletion duration is documented).
    try:
        confirm = bac.get_agent_runtime(agentRuntimeId=runtime_id2)
    except ClientError as exc:
        gone_code, gone_message = exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    else:
        assert confirm["status"] == "DELETING", (
            f"expected the accepted delete to be reflected on an independent read, got {confirm['status']!r}"
        )
        # The delete then completes: the runtime reads as not found.
        gone_code, gone_message = _poll_gone(lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id2))
    assert gone_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {gone_code!r}"
    expected_gone = f"Agent with agentId: {runtime_id2}, accountId: {ctx.account}, and version: null not found!"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"


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


def _poll_gone(read, timeout_s=300.0, interval_s=5.0):
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


def _delete_runtime_and_wait(bac, runtime_id, account, timeout_s=300.0, interval_s=5.0):
    """Delete the runtime (retrying while an endpoint delete is still settling) and wait for it to be gone.

    DeleteAgentRuntime on an id that no longer exists is refused with AccessDeniedException,
    so an already-deleted runtime is detected with a read first."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            bac.get_agent_runtime(agentRuntimeId=runtime_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        try:
            bac.delete_agent_runtime(agentRuntimeId=runtime_id)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
            continue
        break
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
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


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
    import json

    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    # IAM roles are eventually consistent; poll for the role to be visible instead of
    # sleeping blind. CreateAgentRuntime's own trust-policy validation lag is handled
    # separately by _create_agent_runtime_with_role_retry.
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            return role_arn
        except ClientError:
            time.sleep(2)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
