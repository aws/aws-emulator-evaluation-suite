"""guardrail-cannot-be-bypassed-via-parameter-manipulation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "guardrail-cannot-be-bypassed-via-parameter-manipulation"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]

TEXT_MODEL = "amazon.nova-lite-v1:0"
_BLOCKED_MESSAGE = "SIM2REAL_BLOCKED_BY_GUARDRAIL"


def _create_word_guardrail(ctx, word: str) -> tuple[str, str]:
    bedrock_ctl = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-behav-gr-")
    resp = bedrock_ctl.create_guardrail(
        name=name,
        blockedInputMessaging=_BLOCKED_MESSAGE,
        blockedOutputsMessaging=_BLOCKED_MESSAGE,
        wordPolicyConfig={
            "wordsConfig": [
                {
                    "text": word,
                    "inputAction": "BLOCK",
                    "inputEnabled": True,
                    "outputAction": "BLOCK",
                    "outputEnabled": True,
                }
            ]
        },
        tags=[{"key": "sim2real", "value": "guardrail-parameter-manipulation"}],
    )
    guardrail_id = resp["guardrailId"]
    ctx.on_cleanup(lambda: bedrock_ctl.delete_guardrail(guardrailIdentifier=guardrail_id))
    return guardrail_id, resp["version"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A word guardrail still intervenes on case-altered or punctuation-wrapped forms of the word,
    while unrelated content ends the turn without the blocked message."""
    bedrock = ctx.client("bedrock-runtime")
    forbidden = ctx.unique_name("Sim2RealForbiddenPhrase").replace("-", "")
    guardrail_id, version = _create_word_guardrail(ctx, forbidden)

    guardrail_config = {"guardrailIdentifier": guardrail_id, "guardrailVersion": version}

    def _converse(text: str):
        return bedrock.converse(
            modelId=TEXT_MODEL,
            messages=[{"role": "user", "content": [{"text": text}]}],
            guardrailConfig=guardrail_config,
        )

    exact_resp = _converse(f"Please describe {forbidden} in detail.")
    assert exact_resp["stopReason"] == "guardrail_intervened", (
        f"expected guardrail_intervened for the exact forbidden phrase, got {exact_resp['stopReason']!r}"
    )

    # Manipulation attempt 1: alternating case does not bypass the (case-insensitive) word filter.
    mixed_case = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(forbidden))
    mixed_resp = _converse(f"Please describe {mixed_case} in detail.")
    assert mixed_resp["stopReason"] == "guardrail_intervened", (
        f"expected guardrail_intervened for a case-manipulated phrase, got {mixed_resp['stopReason']!r}"
    )

    # Manipulation attempt 2: wrapping the phrase in adjacent punctuation does not bypass the
    # filter either -- the configured word is still present verbatim in the request content.
    punctuated_resp = _converse(f"Tell me about ({forbidden}!) right now.")
    assert punctuated_resp["stopReason"] == "guardrail_intervened", (
        f"expected guardrail_intervened for a punctuation-wrapped phrase, got {punctuated_resp['stopReason']!r}"
    )

    # Positive control: content with no relation to the forbidden phrase passes through normally.
    clean_resp = _converse("What is the capital of France?")
    assert clean_resp["stopReason"] == "end_turn", (
        f"expected end_turn for unrelated content, got {clean_resp['stopReason']!r}"
    )
    clean_text = clean_resp["output"]["message"]["content"][0]["text"]
    assert _BLOCKED_MESSAGE not in clean_text, (
        f"blocked messaging {_BLOCKED_MESSAGE!r} leaked into an unrelated, unblocked response: {clean_text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
