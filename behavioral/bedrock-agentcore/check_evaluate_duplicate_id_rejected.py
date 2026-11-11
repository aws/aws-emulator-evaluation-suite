"""evaluate-duplicate-id-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "evaluate-duplicate-id-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Evaluate with two reference inputs on the same span context fails with ValidationException
    ('Duplicate context found: ...' naming the session and trace ids); one reference input on that
    span gets a result whose error is LogEventMissingException, not a duplicate.
    """
    agentcore = ctx.client("bedrock-agentcore")
    evaluator_id = "Builtin.Helpfulness"
    # traceId/spanId use OTel hex-id conventions; the span itself follows the documented
    # OTel-JSON shape AgentCore Evaluations parses (traceId/spanId/name/kind/
    # startTimeUnixNano/endTimeUnixNano/attributes/status/scope) -- omitting startTimeUnixNano
    # produces a distinct "Field 'start_time' is required" ValidationException, and omitting
    # `scope` produces "Provided input has no spans with supported scope" (the evaluator only
    # recognizes a fixed set of instrumentation-library names, e.g. "strands-agents"), so a
    # complete minimal span is required to reach the duplicate-context check at all.
    # spanId is used only inside the sessionSpans entry: the reference-input spanContext
    # below is trace-level (sessionId + traceId only) -- Evaluate's error message documents
    # that span-level reference inputs ("Remove the spanId from the context...") aren't
    # supported.
    span_id = "a1b2c3d4e5f60789"
    trace_id = "a1b2c3d4e5f6078900112233445566ff"
    session_id = "sim2real-eval-session"
    span_context = {"sessionId": session_id, "traceId": trace_id}
    start_ns = int(time.time() * 1_000_000_000)
    evaluation_input = {
        "sessionSpans": [
            {
                "traceId": trace_id,
                "spanId": span_id,
                "name": "invoke_agent Sim2realAgent",
                "kind": "INTERNAL",
                "startTimeUnixNano": start_ns,
                "endTimeUnixNano": start_ns + 1_000_000_000,
                "attributes": {"gen_ai.operation.name": "invoke_agent", "session.id": session_id},
                "status": {"code": "OK"},
                "scope": {"name": "strands-agents"},
            }
        ]
    }
    duplicate_reference_inputs = [
        {"context": {"spanContext": span_context}, "expectedResponse": {"text": "expected-a"}},
        {"context": {"spanContext": span_context}, "expectedResponse": {"text": "expected-b"}},
    ]

    # Primary assertion: duplicate span-context identifiers -> ValidationException whose
    # message specifically calls out the duplicate context (not just any ValidationException).
    code, message = _error(
        lambda: agentcore.evaluate(
            evaluatorId=evaluator_id,
            evaluationInput=evaluation_input,
            evaluationReferenceInputs=duplicate_reference_inputs,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got [{code}] {message}"
    expected = (
        f"Duplicate context found: session_id='{session_id}' parent_span_id=None "
        f"trace_id='{trace_id}' span_id=None"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Contrast (positive control): a single, non-duplicated reference input on the same
    # evaluator/span must clear the transport layer (200, not the ValidationException
    # above) -- proving the rejection above is conditioned on the actual duplicate
    # context, not a blanket failure of every Evaluate call on this span. The per-result
    # payload is still expected to carry its own errorCode, because the span is synthetic
    # (see module docstring) -- but that errorCode must be the documented, unrelated
    # "missing log event" one, not anything mentioning duplication, or the "positive"
    # control would itself be failing for the very reason under test.
    single_reference_inputs = [
        {"context": {"spanContext": span_context}, "expectedResponse": {"text": "expected-a"}},
    ]
    contrast_response = agentcore.evaluate(
        evaluatorId=evaluator_id,
        evaluationInput=evaluation_input,
        evaluationReferenceInputs=single_reference_inputs,
    )
    results = contrast_response.get("evaluationResults") or []
    assert results, f"non-duplicated Evaluate call returned no evaluationResults: {contrast_response!r}"
    result_error_code = results[0].get("errorCode")
    result_error_message = results[0].get("errorMessage") or ""
    assert result_error_code == "LogEventMissingException" and "duplicate" not in result_error_message.lower(), (
        f"non-duplicated reference input did not clear the duplicate-context check as expected: "
        f"errorCode={result_error_code!r} errorMessage={result_error_message!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError fn raises. An unexpected SUCCESS raises, so a
    target that accepts the duplicate fails naming what it returned."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

