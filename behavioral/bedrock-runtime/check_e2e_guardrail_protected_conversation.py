"""e2e-guardrail-protected-conversation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-guardrail-protected-conversation"
GROUP = "server-side"
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
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    guardrail_id = resp["guardrailId"]
    ctx.on_cleanup(lambda: bedrock_ctl.delete_guardrail(guardrailIdentifier=guardrail_id))
    return guardrail_id, resp["version"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A word-policy guardrail blocks the same content in ApplyGuardrail (GUARDRAIL_INTERVENED) and
    in Converse (stopReason guardrail_intervened), both returning the configured blocked message,
    while unrelated content passes both entry points.
    """
    bedrock = ctx.client("bedrock-runtime")
    forbidden = ctx.unique_name("Sim2RealE2EForbidden").replace("-", "")
    guardrail_id, version = _create_word_guardrail(ctx, forbidden)
    guardrail_config = {"guardrailIdentifier": guardrail_id, "guardrailVersion": version}

    violating_text = f"Can you help me plan {forbidden} for tomorrow?"
    clean_text = "Can you help me plan a birthday party for tomorrow?"

    apply_resp = bedrock.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion=version,
        source="INPUT",
        content=[{"text": {"text": violating_text}}],
    )
    assert apply_resp["action"] == "GUARDRAIL_INTERVENED", (
        f"expected ApplyGuardrail to intervene on violating content, got {apply_resp['action']!r}"
    )
    apply_outputs = apply_resp["outputs"]
    assert len(apply_outputs) == 1, f"expected exactly one blocked output, got {apply_outputs!r}"
    apply_output_text = apply_outputs[0]["text"]
    assert apply_output_text == _BLOCKED_MESSAGE, (
        f"expected ApplyGuardrail's blocked-message substitution, got {apply_output_text!r}"
    )

    apply_clean_resp = bedrock.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion=version,
        source="INPUT",
        content=[{"text": {"text": clean_text}}],
    )
    assert apply_clean_resp["action"] == "NONE", (
        "positive control: ApplyGuardrail must pass unrelated content through unmodified, got "
        f"{apply_clean_resp['action']!r}"
    )

    converse_resp = bedrock.converse(
        modelId=TEXT_MODEL,
        messages=[{"role": "user", "content": [{"text": violating_text}]}],
        guardrailConfig=guardrail_config,
    )
    assert converse_resp["stopReason"] == "guardrail_intervened", (
        f"expected Converse to intervene on violating content, got {converse_resp['stopReason']!r}"
    )
    converse_text = converse_resp["output"]["message"]["content"][0]["text"]
    assert converse_text == _BLOCKED_MESSAGE, (
        f"Converse must apply the identical blocked-message substitution, got {converse_text!r}"
    )

    converse_clean_resp = bedrock.converse(
        modelId=TEXT_MODEL,
        messages=[{"role": "user", "content": [{"text": clean_text}]}],
        guardrailConfig=guardrail_config,
    )
    assert converse_clean_resp["stopReason"] == "end_turn", (
        "positive control: Converse must not intervene on unrelated content, got "
        f"{converse_clean_resp['stopReason']!r}"
    )
    converse_clean_text = converse_clean_resp["output"]["message"]["content"][0]["text"]
    assert _BLOCKED_MESSAGE not in converse_clean_text, (
        f"positive control: clean Converse output must not carry the blocked-message substitution, "
        f"got {converse_clean_text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
