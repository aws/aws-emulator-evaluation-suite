"""invoke-harness-managed-orchestration-result."""
from __future__ import annotations

import json
import random
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-harness-managed-orchestration-result"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]

# The bare foundation-model ID has no on-demand throughput in us-west-2 -- ConverseStream rejects
# it with "Retry your request with the ID or ARN of an inference profile that contains this
# model." The us.* cross-region inference profile is enabled by default, with no explicit
# model-access request, in accounts that have not customized their Bedrock model access grants.
_MODEL_ID = "us.amazon.nova-micro-v1:0"


@tags("axis:happy-path", "cap:c4", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeHarness runs a real server-managed agent loop: asked to sum operands known only at
    run time, the reply contains the correct server-computed answer, which an echoed or canned
    reply cannot produce."""
    iam = ctx.client("iam")
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    role_arn = _create_execution_role(ctx, iam)
    harness_arn, harness_id = _create_harness(ctx, control, role_arn)
    _wait_for_harness_ready(control, harness_id)

    a, b = random.randint(1000, 9999), random.randint(1000, 9999)
    expected = str(a + b)
    prompt = (
        f"Compute {a} + {b}. Reply with ONLY the resulting integer digits, no words, "
        "no punctuation, nothing else."
    )
    runtime_session_id = ("sim2real" + uuid.uuid4().hex + uuid.uuid4().hex)[:80]

    resp = data.invoke_harness(
        harnessArn=harness_arn,
        runtimeSessionId=runtime_session_id,
        messages=[{"role": "user", "content": [{"text": prompt}]}],
    )
    reply_text, error_event = _drain_harness_stream(resp["stream"])

    assert error_event is None, f"harness invocation raised a stream-level error: {error_event}"
    assert reply_text.strip() != "", "harness returned an empty reply"
    assert prompt not in reply_text, "harness echoed the client prompt verbatim instead of answering it"
    assert expected in reply_text.replace(",", ""), (
        f"expected the server-computed sum {expected!r} to appear in the model's reply, got {reply_text!r}"
    )



# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously. The
# runner swallows a cleanup's exception, so a bare delete in on_cleanup leaked even on PASS.
_AC_TRANSITIONAL = ("CREATING", "UPDATING", "DELETING", "SYNCHRONIZING")


def _ac_delete_and_wait(get_status, delete, *, what, timeout_s=600.0, interval_s=5.0):
    """Delete once out of a transitional status, then wait for ResourceNotFound; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = get_status()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if last == "DELETED":
            return
        if last not in _AC_TRANSITIONAL:
            try:
                delete()
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ConflictException", "ValidationException"):
                    raise
                last = f"{last}; delete refused: {exc}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown: {what} still present after {timeout_s}s ({last})")
        time.sleep(interval_s)


def _ac_delete_harness(control, harness_id):
    """Endpoints first (DeleteHarness is refused while one exists); the harness then takes its
    DEFAULT endpoint, managed memory and runtime with it -- none of those can be deleted directly."""
    try:
        pages = control.get_paginator("list_harness_endpoints").paginate(harnessId=harness_id)
        endpoint_names = [
            e["endpointName"] for page in pages for e in page.get("endpoints", []) if e["endpointName"] != "DEFAULT"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    for endpoint_name in endpoint_names:
        _ac_delete_and_wait(
            lambda: control.get_harness_endpoint(harnessId=harness_id, endpointName=endpoint_name)["endpoint"]["status"],
            lambda: control.delete_harness_endpoint(harnessId=harness_id, endpointName=endpoint_name),
            what=f"harness endpoint {endpoint_name}",
        )
    _ac_delete_and_wait(
        lambda: control.get_harness(harnessId=harness_id)["harness"]["status"],
        lambda: control.delete_harness(harnessId=harness_id),
        what=f"harness {harness_id}",
    )

def _create_execution_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-agentcore-harness-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_arn = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    # AmazonBedrockFullAccess predates the bedrock-agentcore action namespace: a managed harness
    # invokes ListEvents/GetEvent on its own auto-provisioned memory resource as part of running the
    # agent loop, and without this the harness returns a runtimeClientError wrapping AccessDenied.
    inline_policy_name = "agentcore-data-plane"
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "bedrock-agentcore:*",
            "Resource": "*",
        }],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps(inline_policy),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name))

    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_arn


def _create_harness(ctx, control, role_arn):
    # HarnessName is ^[a-zA-Z][a-zA-Z0-9_]{0,39}$ -- no dashes, so ctx.unique_name's default
    # separator can't be used; the "sim2real" name prefix is still kept intact.
    harness_name = ctx.unique_name("sim2realharn")[:40]

    def _attempt():
        return control.create_harness(
            harnessName=harness_name,
            executionRoleArn=role_arn,
            model={"bedrockModelConfig": {"modelId": _MODEL_ID}},
            tags={"sim2real-managed": "true"},
        )

    resp = _retry_role_propagation(_attempt)
    harness = resp["harness"]
    harness_arn = harness["arn"]
    harness_id = harness["harnessId"]
    ctx.on_cleanup(lambda: _ac_delete_harness(control, harness_id))
    return harness_arn, harness_id


def _retry_role_propagation(fn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _wait_for_harness_ready(control, harness_id, timeout_s=240.0, interval_s=5.0):
    # HarnessStatus has no ACTIVE member -- the real terminal-success value is READY, and the
    # terminal-failure values are CREATE_FAILED/UPDATE_FAILED/DELETE_FAILED (there is no bare FAILED).
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = control.get_harness(harnessId=harness_id)["harness"]["status"]
        if status == "READY":
            return
        if status.endswith("_FAILED"):
            raise AssertionError(f"harness reached terminal failure status {status!r}")
        time.sleep(interval_s)
    raise AssertionError(f"harness never reached READY within {timeout_s}s (last status={status!r})")


def _drain_harness_stream(stream):
    text_parts = []
    error_event = None
    for event in stream:
        delta_event = event.get("contentBlockDelta")
        if delta_event:
            delta = delta_event.get("delta") or {}
            if delta.get("text"):
                text_parts.append(delta["text"])
        for key in ("internalServerException", "validationException", "runtimeClientError"):
            if event.get(key) is not None:
                error_event = {key: event[key]}
    return "".join(text_parts), error_event


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
