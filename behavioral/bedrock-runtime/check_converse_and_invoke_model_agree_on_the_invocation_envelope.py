"""converse-and-invoke-model-agree-on-the-invocation-envelope."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "converse-and-invoke-model-agree-on-the-invocation-envelope"
GROUP = "data-plane"
SERVICES = ["bedrock-runtime"]


# Pinned as a module constant: the native body below is model-specific, so the model id and the
# body shape have to move together.
MODEL_ID = "amazon.nova-lite-v1:0"

_PROMPT = "Reply with exactly the single word PONG and nothing else."
#: The inference settings, expressed once and rendered into both request forms, so the two calls
#: differ ONLY in which operation carries them.
_MAX_TOKENS = 64
_TEMPERATURE = 0.0
_TOP_P = 1.0

#: Members the two operations both carry in their response BODY. Converse's `metrics`,
#: `performanceConfig` and `trace` are deliberately excluded: InvokeModel binds its equivalents to
#: X-Amzn-Bedrock-* HTTP headers, so demanding them in the body would fail a correct target.
_SHARED_MEMBERS = ("output", "stopReason", "usage")
_USAGE_MEMBERS = ("inputTokens", "outputTokens", "totalTokens")

#: Nova's native InvokeModel body always reports these two prompt-cache counters inside `usage`,
#: which Converse does not translate into its own `usage` envelope when the request carries no
#: cachePoint block. This is the only permitted difference between the two usage member sets.
_NATIVE_ONLY_CACHE_MEMBERS = ("cacheReadInputTokenCount", "cacheWriteInputTokenCount")


def _text(payload) -> str:
    content = payload["output"]["message"]["content"]
    assert content, f"the turn returned an empty content list; output={payload['output']!r}"
    non_text = [sorted(b) for b in content if "text" not in b]
    assert not non_text, (
        f"a plain-text prompt with no toolConfig must come back as text blocks only; got "
        f"non-text blocks {non_text!r}"
    )
    return "".join(b["text"] for b in content)


def _check_envelope(label: str, payload: dict) -> None:
    missing = [m for m in _SHARED_MEMBERS if m not in payload]
    assert not missing, (
        f"the {label} response body is missing required envelope members {missing!r}; it carried "
        f"{sorted(payload)!r}"
    )
    message = payload["output"]["message"]
    assert message["role"] == "assistant", (
        f"the {label} response's output message must be attributed to the assistant; got "
        f"role={message['role']!r}"
    )
    usage = payload["usage"]
    usage_missing = [m for m in _USAGE_MEMBERS if m not in usage]
    assert not usage_missing, (
        f"the {label} response's usage is missing required members {usage_missing!r}; it carried "
        f"{sorted(usage)!r}"
    )
    assert usage["totalTokens"] == usage["inputTokens"] + usage["outputTokens"], (
        f"TokenUsage.totalTokens is documented as the total of input and generated tokens; the "
        f"{label} response reported {usage!r}"
    )
    assert usage["inputTokens"] > 0 and usage["outputTokens"] > 0, (
        f"the {label} invocation must report non-zero token usage, else the equality below is "
        f"vacuous; usage={usage!r}"
    )


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Converse and native InvokeModel, given the same Nova prompt, report identical token usage,
    the same stopReason and the same content-block shape; native usage adds only the two
    zero-valued prompt-cache counters that Converse does not translate.
    """
    rt = ctx.client("bedrock-runtime")
    messages = [{"role": "user", "content": [{"text": _PROMPT}]}]
    inference = {"maxTokens": _MAX_TOKENS, "temperature": _TEMPERATURE, "topP": _TOP_P}

    # --- Path A: the unified Converse API.
    conv = rt.converse(modelId=MODEL_ID, messages=messages, inferenceConfig=inference)
    _check_envelope("Converse", conv)
    conv_text = _text(conv)
    assert "PONG" in conv_text.upper(), (
        f"the Converse invocation must be a real generation carrying the forced token, else the "
        f"agreement below is between two failures; got {conv_text!r}"
    )

    # --- Path B: the provider-native body through InvokeModel. Same messages, same inference
    # settings, rendered into the native JSON that Nova accepts.
    native_body = json.dumps({"messages": messages, "inferenceConfig": inference}, sort_keys=True)
    raw = rt.invoke_model(
        modelId=MODEL_ID, body=native_body,
        contentType="application/json", accept="application/json")
    assert raw["contentType"] == "application/json", (
        f"accept=application/json must be honoured on the response Content-Type; got "
        f"{raw['contentType']!r}"
    )
    inv = json.loads(raw["body"].read())
    _check_envelope("InvokeModel", inv)
    inv_text = _text(inv)
    assert "PONG" in inv_text.upper(), (
        f"the native InvokeModel invocation must be a real generation carrying the forced token; "
        f"got {inv_text!r}"
    )

    # --- The terminal assertions: agreements between two different operations.
    # With no cachePoint, Converse usage is the core three members; native InvokeModel usage is
    # those three plus cacheReadInputTokenCount/cacheWriteInputTokenCount, both zero.
    assert sorted(conv["usage"]) == sorted(_USAGE_MEMBERS), (
        f"Converse must report exactly the core usage members for a request with no cachePoint "
        f"block; got {sorted(conv['usage'])!r}"
    )
    native_extra = sorted(set(inv["usage"]) - set(_USAGE_MEMBERS))
    assert native_extra == sorted(_NATIVE_ONLY_CACHE_MEMBERS), (
        f"the native InvokeModel body's usage must carry the core members plus exactly the "
        f"prompt-cache counters that Converse does not translate into its usage envelope; got "
        f"extra members {native_extra!r} (full usage {inv['usage']!r})"
    )
    inv_cache_read = inv["usage"]["cacheReadInputTokenCount"]
    inv_cache_write = inv["usage"]["cacheWriteInputTokenCount"]
    assert inv_cache_read == 0 and inv_cache_write == 0, (
        f"this request carries no cachePoint block, so the native cache counters must read zero; "
        f"got cacheReadInputTokenCount={inv_cache_read!r} "
        f"cacheWriteInputTokenCount={inv_cache_write!r}"
    )
    conv_blocks = [sorted(b) for b in conv["output"]["message"]["content"]]
    inv_blocks = [sorted(b) for b in inv["output"]["message"]["content"]]
    assert conv_blocks == inv_blocks, (
        f"the two operations must shape the assistant turn identically for the same prompt; "
        f"Converse content block keys {conv_blocks!r} InvokeModel {inv_blocks!r}"
    )
    assert inv["stopReason"] == conv["stopReason"], (
        f"the same prompt under the same maxTokens={_MAX_TOKENS} budget must stop for the same "
        f"reason on both operations; Converse={conv['stopReason']!r} "
        f"InvokeModel={inv['stopReason']!r} (Converse text {conv_text!r}, InvokeModel text "
        f"{inv_text!r})"
    )
    # Input tokenisation depends only on what the model is shown, and for Nova the native body IS
    # the Converse body, so the two paths must agree exactly on every member Converse reports.
    for member in _USAGE_MEMBERS:
        assert inv["usage"][member] == conv["usage"][member], (
            f"Converse is a translation of the native path, so the same logical prompt must be "
            f"charged identical {member} on both operations; Converse={conv['usage'][member]!r} "
            f"InvokeModel={inv['usage'][member]!r} (full usage Converse={conv['usage']!r} "
            f"InvokeModel={inv['usage']!r})"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
