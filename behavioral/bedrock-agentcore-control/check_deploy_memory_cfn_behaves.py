"""deploy-memory-cfn-behaves."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-memory-cfn-behaves"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Memory:
    Type: AWS::BedrockAgentCore::Memory
    Properties:
      Name: '__MEMORY_NAME__'
      EventExpiryDuration: 7
      Tags:
        sim2real:managed: 'true'
        sim2real:prefix: sim2real-memory
Outputs:
  MemoryId:
    Value: !GetAtt Memory.MemoryId
"""


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CloudFormation-deployed Memory is writable/readable via the data plane, not just Get-able."""
    from botocore.exceptions import ClientError

    control = ctx.client("bedrock-agentcore-control")
    data_plane = ctx.client("bedrock-agentcore")
    cfn = ctx.client("cloudformation")

    memory_name = _alnum_name(ctx, "sim2realCfnMem")
    template_body = _TEMPLATE.replace("__MEMORY_NAME__", memory_name)

    stack_name = _deploy_cfn(ctx, cfn, template_body)
    outputs = _stack_outputs(cfn, stack_name)
    memory_id = outputs["MemoryId"]

    try:
        active = _poll_until(
            lambda: control.get_memory(memoryId=memory_id),
            lambda r: r["memory"]["status"] == "ACTIVE",
            timeout_s=180.0,
            interval_s=5.0,
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "AccessDeniedException":
            raise AssertionError(
                "this account's execution identity is denied bedrock-agentcore:GetMemory; "
                "the Memory control-plane read path cannot be exercised in this sandbox"
            )
        raise
    assert active["memory"]["name"] == memory_name, (
        f"expected CFN-deployed memory name {memory_name!r}, got {active['memory']['name']!r}"
    )

    actor_id = "sim2real-actor"
    session_id = "sim2real-session-" + memory_id[-10:]
    data_plane.create_event(
        memoryId=memory_id,
        actorId=actor_id,
        sessionId=session_id,
        eventTimestamp=datetime.datetime.now(datetime.timezone.utc),
        payload=[{"conversational": {"content": {"text": "sim2real memory round-trip"}, "role": "USER"}}],
    )

    def _find_event():
        resp = data_plane.list_events(memoryId=memory_id, actorId=actor_id, sessionId=session_id)
        return resp.get("events", [])

    events = _poll_until(_find_event, lambda evs: len(evs) >= 1, timeout_s=60.0, interval_s=3.0)
    texts = [
        block.get("conversational", {}).get("content", {}).get("text")
        for ev in events
        for block in ev.get("payload", [])
    ]
    assert "sim2real memory round-trip" in texts, (
        f"data-plane list_events on the CFN-deployed memory did not return the created event; got texts={texts!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    code, message = _error(lambda: control.get_memory(memoryId=memory_id))
    assert code == "ResourceNotFoundException", (
        f"expected GetMemory on the stack-deleted memory to fail with ResourceNotFoundException, got {code!r}"
    )
    expected = f"Resource not found during GetMemory: Failed to retrieve memory item for ID: {memory_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "_")


def _deploy_cfn(ctx, cfn, template_body: str) -> str:
    stack_name = ctx.unique_name("sim2real-memory-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-memory"},
        ],
    )
    ctx.on_cleanup(lambda: _destroy_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    return stack_name


def _destroy_stack(cfn, stack_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
    except ClientError as exc:
        if not (
            (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _stack_outputs(cfn, stack_name: str) -> dict:
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; AssertionError if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
