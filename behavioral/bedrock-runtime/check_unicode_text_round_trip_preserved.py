"""unicode-text-round-trip-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "unicode-text-round-trip-preserved"
GROUP = "server-side"
SERVICES = ["bedrock-runtime"]

TEXT_MODEL = "amazon.nova-lite-v1:0"
_MARKER = "\u3053\u3093\u306b\u3061\u306f-\U0001F30D-\u00e9\u00fc-\u4e2d\u6587\u6d4b\u8bd5"  # kanji/emoji/accents/CJK


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse and InvokeModel preserve multi-byte unicode (CJK, a non-BMP emoji, accents).

    A verbatim-echo prompt must return the exact marker, so neither direction mangles the encoding.
    """
    bedrock = ctx.client("bedrock-runtime")
    instruction = (
        f'Repeat back exactly and only this text, with no other words before or after it: "{_MARKER}"'
    )

    converse_resp = bedrock.converse(
        modelId=TEXT_MODEL,
        messages=[{"role": "user", "content": [{"text": instruction}]}],
        inferenceConfig={"temperature": 0, "topP": 1, "maxTokens": 100},
    )
    converse_text = converse_resp["output"]["message"]["content"][0]["text"]
    assert _MARKER in converse_text, f"marker not preserved by Converse: {converse_text!r}"

    body = json.dumps(
        {"messages": [{"role": "user", "content": [{"text": instruction}]}], "inferenceConfig": {"maxTokens": 100, "temperature": 0, "topP": 1}}
    ).encode("utf-8")
    invoke_resp = bedrock.invoke_model(modelId=TEXT_MODEL, body=body, contentType="application/json")
    invoke_text = json.loads(invoke_resp["body"].read())["output"]["message"]["content"][0]["text"]
    assert _MARKER in invoke_text, f"marker not preserved by InvokeModel: {invoke_text!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
