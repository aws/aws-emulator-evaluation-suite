"""bedrock-runtime-converse-tool-result-with-an-unknown-tool-use-id-rejected."""
from __future__ import annotations

import random

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bedrock-runtime-converse-tool-result-with-an-unknown-tool-use-id-rejected"
GROUP = 'overly-permissive'
SERVICES = ['bedrock-runtime']

# Pinned: the check depends on this model reliably choosing the tool and supporting toolChoice.
MODEL_ID = "amazon.nova-lite-v1:0"

_TOOL_NAME = "get_stock_price"
_SYMBOL = "ZZQX"
_QUESTION = (
    f"What is the current share price of {_SYMBOL}? Use the {_TOOL_NAME} tool, then report "
    f"the price_usd value exactly as the tool returned it."
)
_TOOL_CONFIG = {
    "tools": [{"toolSpec": {
        "name": _TOOL_NAME,
        "description": "Get the current share price in USD for a ticker symbol.",
        "inputSchema": {"json": {
            "type": "object",
            "properties": {"symbol": {"type": "string", "description": "The ticker symbol."}},
            "required": ["symbol"],
        }},
    }}],
}
# Turn 1 only: a mandatory toolChoice on the follow-up turn makes the model call the tool again
# instead of answering.
_TOOL_CONFIG_FORCED = dict(_TOOL_CONFIG, toolChoice={"tool": {"name": _TOOL_NAME}})
_INFERENCE = {"maxTokens": 500, "temperature": 0.0}


def _error_code(fn):
    """Return (code, message) of the ClientError fn() raises; fail if the call succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        return (exc.response.get("Error", {}).get("Code", ""),
                exc.response.get("Error", {}).get("Message", ""))
    raise AssertionError(
        f"a toolResult naming a toolUseId the service never issued was ACCEPTED. That is an "
        f"over-permissiveness finding, not a code mismatch: the conversation the model was shown "
        f"is not the one it produced. response={resp!r}"
    )


def _text(resp):
    return "".join(b.get("text", "") for b in resp["output"]["message"]["content"])


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A toolResult whose toolUseId differs by one character from the minted id is refused with a
    ValidationException naming both ids, while the correctly addressed history is accepted.

    Reference: https://docs.aws.amazon.com/bedrock/latest/userguide/tool-use.html
    """
    rt = ctx.client("bedrock-runtime")

    # A value the model cannot know and that appears nowhere before the toolResult carries it.
    price = f"{random.randint(300, 899)}.{random.randint(10, 99)}"
    user_turn = {"role": "user", "content": [{"text": _QUESTION}]}

    first = rt.converse(modelId=MODEL_ID, toolConfig=_TOOL_CONFIG_FORCED, messages=[user_turn],
                        inferenceConfig=_INFERENCE)
    assert first["stopReason"] == "tool_use", (
        f"a mandatory toolChoice must stop the turn to call the tool; got "
        f"{first['stopReason']!r} content={first['output']['message']['content']!r}"
    )
    uses = [b["toolUse"] for b in first["output"]["message"]["content"] if "toolUse" in b]
    assert len(uses) == 1, (
        f"exactly one toolUse block expected; got {first['output']['message']['content']!r}"
    )
    minted = uses[0]["toolUseId"]
    assert minted, f"the service must mint a toolUseId; got {uses[0]!r}"
    assert price not in _text(first), (
        f"the price must not appear before the tool returned it, otherwise the control leg proves "
        f"nothing; price={price!r} turn-1 text={_text(first)!r}"
    )

    def _history(tool_use_id):
        return [
            user_turn,
            first["output"]["message"],
            {"role": "user", "content": [{"toolResult": {
                "toolUseId": tool_use_id,
                "content": [{"json": {"symbol": _SYMBOL, "price_usd": price}}],
                "status": "success",
            }}]},
        ]

    # Control first: without it a refusal below is indistinguishable from a malformed history.
    allowed = rt.converse(modelId=MODEL_ID, toolConfig=_TOOL_CONFIG,
                          messages=_history(minted), inferenceConfig=_INFERENCE)
    allowed_text = _text(allowed)
    assert price in allowed_text, (
        f"the value supplied through the correctly addressed toolResult must reach the answer; "
        f"price={price!r} answer={allowed_text!r}"
    )
    assert allowed["usage"]["outputTokens"] > 0, (
        f"the control turn must be a real generation; usage={allowed['usage']!r}"
    )

    # Break exactly ONE thing: the same history, with the last character of the id changed.
    tail = minted[-1]
    mutated = minted[:-1] + ("A" if tail != "A" else "B")
    assert mutated != minted and len(mutated) == len(minted), (
        f"the mutation must differ from the minted id in exactly one character; minted "
        f"{minted!r} mutated {mutated!r}"
    )
    code, message = _error_code(
        lambda: rt.converse(modelId=MODEL_ID, toolConfig=_TOOL_CONFIG,
                            messages=_history(mutated), inferenceConfig=_INFERENCE)
    )
    assert code == "ValidationException", (
        f"a toolResult addressed to an id the service never minted must be refused with "
        f"ValidationException; got {code!r} message={message!r}"
    )
    # Naming both ids proves the service matched on the identifier, not the block shape.
    assert minted in message, (
        f"the refusal must name the toolUseId it expected ({minted!r}), otherwise it is not "
        f"distinguishable from a generic schema complaint; got {message!r}"
    )
    assert mutated in message, (
        f"the refusal must name the id it actually found ({mutated!r}); got {message!r}"
    )
    expected = (
        f"Expected toolResult blocks at messages.2.content for the following Ids: {minted}, "
        f"but found: {mutated}"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # The correct history is still accepted, so the refusal was about the id, not session state.
    again = rt.converse(modelId=MODEL_ID, toolConfig=_TOOL_CONFIG,
                        messages=_history(minted), inferenceConfig=_INFERENCE)
    assert price in _text(again), (
        f"the correctly addressed history must still be accepted after the refusal; "
        f"price={price!r} answer={_text(again)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
