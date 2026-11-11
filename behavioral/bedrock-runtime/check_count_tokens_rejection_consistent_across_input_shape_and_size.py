"""count-tokens-rejection-consistent-across-input-shape-and-size."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "count-tokens-rejection-consistent-across-input-shape-and-size"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]

MODEL_ID = "amazon.nova-lite-v1:0"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CountTokens rejects an unsupported but invocable model with one identical ValidationException
    across Converse- and InvokeModel-shaped inputs, short and long; a Converse call is the control.
    """
    brt = ctx.client("bedrock-runtime")

    short_text = "Hello there."
    long_text = "Hello there. " * 200

    control = brt.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": short_text}]}],
        inferenceConfig={"maxTokens": 16},
    )
    assert control["usage"]["inputTokens"] > 0, (
        f"positive control: Converse against {MODEL_ID!r} must actually generate, else the "
        f"account/model cannot support the claim that CountTokens rejects it specifically; "
        f"usage={control['usage']!r}"
    )

    converse_short = _error_code_and_message(
        lambda: brt.count_tokens(
            modelId=MODEL_ID,
            input={"converse": {"messages": [{"role": "user", "content": [{"text": short_text}]}]}},
        )
    )
    converse_long = _error_code_and_message(
        lambda: brt.count_tokens(
            modelId=MODEL_ID,
            input={"converse": {"messages": [{"role": "user", "content": [{"text": long_text}]}]}},
        )
    )
    invoke_short = _error_code_and_message(
        lambda: brt.count_tokens(
            modelId=MODEL_ID,
            input={
                "invokeModel": {
                    "body": json.dumps(
                        {
                            "messages": [{"role": "user", "content": [{"text": short_text}]}],
                            "inferenceConfig": {"maxTokens": 16},
                        }
                    )
                }
            },
        )
    )
    invoke_long = _error_code_and_message(
        lambda: brt.count_tokens(
            modelId=MODEL_ID,
            input={
                "invokeModel": {
                    "body": json.dumps(
                        {
                            "messages": [{"role": "user", "content": [{"text": long_text}]}],
                            "inferenceConfig": {"maxTokens": 16},
                        }
                    )
                }
            },
        )
    )

    for label, (code, message) in (
        ("converse_short", converse_short),
        ("converse_long", converse_long),
        ("invoke_short", invoke_short),
        ("invoke_long", invoke_long),
    ):
        assert code == "ValidationException", f"{label}: expected ValidationException, got {code!r}"

    messages_seen = {converse_short[1], converse_long[1], invoke_short[1], invoke_long[1]}
    assert len(messages_seen) == 1, (
        f"CountTokens gave different rejection messages across input shape/size -- the rejection "
        f"is not actually consistent: {messages_seen!r}"
    )


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        "CountTokens was expected to be refused for a model it doesn't support, but succeeded"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
