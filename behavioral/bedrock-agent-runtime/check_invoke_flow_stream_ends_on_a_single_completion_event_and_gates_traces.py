"""invoke-flow-stream-ends-on-a-single-completion-event-and-gates-traces."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-flow-stream-ends-on-a-single-completion-event-and-gates-traces"
GROUP = "ordering"
SERVICES = ["bedrock-agent-runtime"]

_INPUT_NODE = "FlowInputNode"
_OUTPUT_NODE = "FlowOutputNode"

# Bounds for prepare_flow reaching Prepared and for a new role becoming assumable by Bedrock.
_PREPARE_S = 150.0
_IAM_S = 90.0

# Modelled FlowResponseStream non-exception members (api-models-aws 2023-07-26). Used only to
# name what was UNEXPECTED in a failure message -- never as an accept-set (an accept-set equal
# to the full modelled union cannot fail).
_KNOWN_EVENTS = ("flowOutputEvent", "flowCompletionEvent", "flowTraceEvent", "flowMultiTurnInputRequestEvent")


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeFlow's response stream terminates in exactly one flowCompletionEvent(SUCCESS) after
    echoing the input document byte-for-byte, and flowTraceEvents appear only when enableTrace
    is set."""
    agent = ctx.client("bedrock-agent")
    runtime = ctx.client("bedrock-agent-runtime")

    flow_id, alias_id = _create_passthrough_flow(ctx, agent)

    # ---- Arm A: no enableTrace. Nonce A must come back verbatim. ----
    nonce_a = ctx.unique_name("sim2real-flowdoc-a-")
    events_a, exec_id_a = _invoke_and_collect(ctx, runtime, flow_id, alias_id, nonce_a, enable_trace=False)
    _assert_framing(events_a, nonce_a, arm="A (enableTrace omitted)")

    trace_a = [i for i, e in enumerate(events_a) if "flowTraceEvent" in e]
    assert trace_a == [], (
        f"arm A omitted enableTrace, so the stream must carry ZERO flowTraceEvent; got "
        f"{len(trace_a)} at indices {trace_a} out of {len(events_a)} events"
    )

    # ---- Arm B: the twin control, same flow and alias, enableTrace=True, DIFFERENT nonce. ----
    # Running an identical-wiring positive in the same instant is what makes arm A's absence of
    # traces evidence about the flag rather than evidence about the target having no traces at
    # all. The distinct nonce also fails a target that returns a canned blob.
    nonce_b = ctx.unique_name("sim2real-flowdoc-b-")
    events_b, exec_id_b = _invoke_and_collect(ctx, runtime, flow_id, alias_id, nonce_b, enable_trace=True)
    _assert_framing(events_b, nonce_b, arm="B (enableTrace=True)")

    trace_b = [i for i, e in enumerate(events_b) if "flowTraceEvent" in e]
    assert len(trace_b) >= 1, (
        f"arm B set enableTrace=True on the same flow and alias that arm A drove seconds "
        f"earlier, so the stream must carry at least one flowTraceEvent; got 0 out of "
        f"{len(events_b)} events, event keys seen: {sorted({k for e in events_b for k in e})}"
    )

    completion_idx_b = [i for i, e in enumerate(events_b) if "flowCompletionEvent" in e][0]
    late_traces = [i for i in trace_b if i > completion_idx_b]
    assert late_traces == [], (
        f"arm B yielded flowTraceEvent(s) at indices {late_traces} AFTER the terminal "
        f"flowCompletionEvent at index {completion_idx_b}; the completion event must be last"
    )

    assert exec_id_a != exec_id_b, (
        f"two InvokeFlow calls on the same alias returned the same executionId "
        f"{exec_id_a!r}; each invocation is a distinct execution"
    )

    # ---- Negative: an input addressed to a node the flow does not have. ----
    # ALWAYS-INVALID-INPUT class: no restore beat exists, because "NoSuchInputNode" can
    # never become a node of this prepared flow. The positive control is arms A and B above,
    # on this exact flow and alias, and is re-proven after the negative below.
    bogus_node = "NoSuchInputNode"  # satisfies NodeName's pattern, so this is a semantic refusal
    # InvokeFlow does not validate inputs[].nodeName up front: the call returns 200 and the
    # refusal arrives as a stream-framed dependencyFailedException, because the flow's real input
    # node received no input. `_error_code` consumes the stream so the exception surfaces.
    code = _error_code(
        lambda: [
            dict(e)
            for e in runtime.invoke_flow(
                flowIdentifier=flow_id,
                flowAliasIdentifier=alias_id,
                inputs=[{"nodeName": bogus_node, "nodeOutputName": "document", "content": {"document": "x"}}],
            )["responseStream"]
        ]
    )
    assert code == "dependencyFailedException", (
        f"InvokeFlow with inputs[0].nodeName={bogus_node!r}, which is not a node of the "
        f"prepared flow, must be rejected because the flow's real input node "
        f"{_INPUT_NODE!r} then has no input; measured on real AWS as a stream-framed "
        f"dependencyFailedException, not a synchronous ClientError; got {code!r}"
    )

    # Re-prove the wiring: the identical shape with the REAL node name still succeeds, so the
    # rejection above was about the node name and not about the flow having become unusable.
    nonce_c = ctx.unique_name("sim2real-flowdoc-c-")
    events_c, _ = _invoke_and_collect(ctx, runtime, flow_id, alias_id, nonce_c, enable_trace=False)
    _assert_framing(events_c, nonce_c, arm="C (post-negative positive control)")

    # ---- Terminal read: an independent operation, at the control plane, on a different
    # client, proving the three data-plane invocations did not advance the flow's state.
    status = agent.get_flow(flowIdentifier=flow_id)["status"]
    assert status == "Prepared", (
        f"after 3 successful InvokeFlow calls and 1 rejected one, GetFlow.status must still be "
        f"'Prepared' (a data-plane read must not advance control state); got {status!r}"
    )


def _assert_framing(events: list[dict], expected_doc: str, *, arm: str) -> None:
    """The completion, reason and byte-fidelity contract both positive arms must satisfy."""
    assert events, f"arm {arm}: InvokeFlow yielded an empty response stream"

    # No exception member may appear in a stream that is supposed to have succeeded. Asserted as
    # a NEGATIVE over the key names so it can actually fail (an accept-set equal to the modelled
    # union could not).
    bad = [k for e in events for k in e if k.endswith("Exception")]
    assert bad == [], f"arm {arm}: response stream carried error member(s) {bad}: {events}"

    unknown = [k for e in events for k in e if k not in _KNOWN_EVENTS and not k.endswith("Exception")]
    assert unknown == [], (
        f"arm {arm}: response stream carried member(s) {unknown} that are not in the modelled "
        f"FlowResponseStream union {list(_KNOWN_EVENTS)}"
    )

    multiturn = [i for i, e in enumerate(events) if "flowMultiTurnInputRequestEvent" in e]
    assert multiturn == [], (
        f"arm {arm}: a two-node Input->Output flow cannot request further input, but the stream "
        f"carried flowMultiTurnInputRequestEvent at indices {multiturn}"
    )

    completion_idx = [i for i, e in enumerate(events) if "flowCompletionEvent" in e]
    assert len(completion_idx) == 1, (
        f"arm {arm}: expected EXACTLY ONE flowCompletionEvent, got {len(completion_idx)} at "
        f"indices {completion_idx} out of {len(events)} events"
    )
    assert completion_idx[0] == len(events) - 1, (
        f"arm {arm}: flowCompletionEvent must be the LAST event in the stream; it was at index "
        f"{completion_idx[0]} of {len(events)} events, followed by "
        f"{[sorted(e) for e in events[completion_idx[0] + 1:]]}"
    )

    reason = events[completion_idx[0]]["flowCompletionEvent"]["completionReason"]
    assert reason == "SUCCESS", (
        f"arm {arm}: a two-node passthrough flow driven to completion must report "
        f"completionReason 'SUCCESS'; got {reason!r}"
    )

    outputs = [e["flowOutputEvent"] for e in events if "flowOutputEvent" in e]
    assert len(outputs) == 1, (
        f"arm {arm}: a flow with exactly one Output node must emit exactly one flowOutputEvent; "
        f"got {len(outputs)}: {outputs}"
    )
    out = outputs[0]
    assert out["nodeName"] == _OUTPUT_NODE, (
        f"arm {arm}: flowOutputEvent.nodeName must name this flow's output node "
        f"{_OUTPUT_NODE!r}; got {out['nodeName']!r}"
    )
    # FlowOutputEvent.nodeType is @required in the model, yet a successful InvokeFlow omits the
    # key; the assertion follows what the service sends.
    assert "nodeType" not in out, (
        f"arm {arm}: flowOutputEvent carried nodeType={out.get('nodeType')!r}, but a real "
        f"InvokeFlow response never carries this key even though the model marks it @required; "
        f"a target that starts sending it has changed the contract this check measures"
    )
    # Byte fidelity through the flow: the Output node's expression is $.data, so the document
    # that comes out must be the exact per-run nonce that went in. A target returning a fixed
    # or paraphrased payload fails here, as the nonce is minted per run.
    assert out["content"]["document"] == expected_doc, (
        f"arm {arm}: the Input->Output flow must echo its input document verbatim; sent "
        f"{expected_doc!r}, flowOutputEvent carried {out['content']['document']!r}"
    )


def _invoke_and_collect(ctx, runtime, flow_id: str, alias_id: str, doc: str, *, enable_trace: bool):
    """Drive InvokeFlow and materialise the stream IN ORDER. Retries only IAM propagation."""
    kwargs: dict = dict(
        flowIdentifier=flow_id,
        flowAliasIdentifier=alias_id,
        inputs=[{"nodeName": _INPUT_NODE, "nodeOutputName": "document", "content": {"document": doc}}],
    )
    if enable_trace:
        kwargs["enableTrace"] = True

    resp = _retry_on_role_propagation(lambda: runtime.invoke_flow(**kwargs))
    events = [dict(event) for event in resp["responseStream"]]

    exec_id = resp.get("executionId")
    assert exec_id, (
        f"InvokeFlow response must carry a non-empty executionId "
        f"(x-amz-bedrock-flow-execution-id); got {exec_id!r}"
    )
    return events, exec_id


def _create_passthrough_flow(ctx, agent) -> tuple[str, str]:
    """Create-or-nothing: every id is minted here, so there is nothing to adopt."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-invflow-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real InvokeFlow framing check (Input->Output, no model call)",
        Tags=[{"Key": "sim2real-check", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _quiet(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = "sim2real-invflow-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "bedrock:GetFlow", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: _quiet(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))

    definition = {
        "nodes": [
            {"type": "Input", "name": _INPUT_NODE, "outputs": [{"name": "document", "type": "String"}]},
            {
                "type": "Output",
                "name": _OUTPUT_NODE,
                "inputs": [{"name": "document", "type": "String", "expression": "$.data"}],
            },
        ],
        "connections": [
            {
                "name": "InputToOutput",
                "source": _INPUT_NODE,
                "target": _OUTPUT_NODE,
                "type": "Data",
                "configuration": {"data": {"sourceOutput": "document", "targetInput": "document"}},
            }
        ],
    }

    flow_id = _retry_on_role_propagation(
        lambda: agent.create_flow(
            name=ctx.unique_name("sim2realinvflow"),
            executionRoleArn=role_arn,
            definition=definition,
            tags={"sim2real-check": CHECK[:250]},
        )
    )["id"]
    ctx.on_cleanup(
        lambda: _quiet(lambda: agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True))
    )

    _retry_on_role_propagation(lambda: agent.prepare_flow(flowIdentifier=flow_id))
    _poll_until(
        lambda: agent.get_flow(flowIdentifier=flow_id)["status"],
        lambda s: s == "Prepared",
        timeout_s=_PREPARE_S,
        interval_s=3.0,
        description="flow status to reach Prepared (terminal set excludes Failed so a failed "
        "prepare times out loudly rather than being accepted)",
    )

    version = agent.create_flow_version(flowIdentifier=flow_id)["version"]
    ctx.on_cleanup(
        lambda: _quiet(lambda: agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=version))
    )

    alias_id = agent.create_flow_alias(
        flowIdentifier=flow_id,
        name=ctx.unique_name("sim2realinvflowalias"),
        routingConfiguration=[{"flowVersion": version}],
        tags={"sim2real-check": CHECK[:250]},
    )["id"]
    ctx.on_cleanup(
        lambda: _quiet(lambda: agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id))
    )
    return flow_id, alias_id


def _error_code(fn) -> str:
    """Return the ClientError code, or RAISE on unexpected success.

    Never returns a falsy sentinel: a sentinel would turn an over-permissive target's
    acceptance into a mere code mismatch.
    """
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry that RAISES on timeout (never returns its last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last value: {last!r}")


def _retry_on_role_propagation(fn, *, timeout_s: float = _IAM_S, interval_s: float = 5.0):
    """IAM is eventually consistent: bedrock.amazonaws.com may not yet be able to assume a role
    created seconds ago. Bounded, and RAISES on exhaustion. Only the two propagation-shaped
    codes are retried; every other ClientError propagates immediately."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDeniedException", "ValidationException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"IAM role never propagated within {timeout_s}s: {last_exc}")


def _quiet(fn) -> None:
    """Teardown-only best effort. Never used on an assertion path."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
