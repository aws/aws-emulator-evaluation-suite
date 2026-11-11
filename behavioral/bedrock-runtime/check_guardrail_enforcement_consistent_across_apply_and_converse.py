"""guardrail-enforcement-consistent-across-apply-and-converse."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "guardrail-enforcement-consistent-across-apply-and-converse"
GROUP = "server-side"
SERVICES = ["bedrock-runtime"]

TEXT_MODEL = "amazon.nova-lite-v1:0"
_BLOCKED_MESSAGE = "SIM2REAL_BLOCKED_MESSAGE_CONSISTENCY"


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
    """ApplyGuardrail and Converse's guardrail trace report the same matched custom word and the
    BLOCKED action for one guardrail, so enforcement agrees at the assessment-detail level."""
    bedrock = ctx.client("bedrock-runtime")
    forbidden = ctx.unique_name("Sim2RealConsistency").replace("-", "")
    guardrail_id, version = _create_word_guardrail(ctx, forbidden)

    violating_text = f"I would like to discuss {forbidden} with you."

    apply_resp = bedrock.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion=version,
        source="INPUT",
        content=[{"text": {"text": violating_text}}],
    )
    assert apply_resp["action"] == "GUARDRAIL_INTERVENED", (
        f"expected ApplyGuardrail to intervene on the forbidden word, got action={apply_resp['action']!r}"
    )
    apply_custom_words = apply_resp["assessments"][0]["wordPolicy"]["customWords"]
    assert len(apply_custom_words) == 1, (
        f"expected exactly 1 ApplyGuardrail customWords match, got {apply_custom_words!r}"
    )
    apply_match = apply_custom_words[0]["match"]
    apply_action = apply_custom_words[0]["action"]

    converse_resp = bedrock.converse(
        modelId=TEXT_MODEL,
        messages=[{"role": "user", "content": [{"text": violating_text}]}],
        guardrailConfig={
            "guardrailIdentifier": guardrail_id,
            "guardrailVersion": version,
            "trace": "enabled",
        },
    )
    assert converse_resp["stopReason"] == "guardrail_intervened", (
        f"expected Converse to stop with guardrail_intervened, got stopReason={converse_resp['stopReason']!r}"
    )
    input_assessment = converse_resp["trace"]["guardrail"]["inputAssessment"]
    assert len(input_assessment) >= 1, (
        f"expected at least 1 Converse trace inputAssessment entry, got {input_assessment!r}"
    )
    converse_assessment = next(iter(input_assessment.values()))
    converse_custom_words = converse_assessment["wordPolicy"]["customWords"]
    assert len(converse_custom_words) == 1, (
        f"expected exactly 1 Converse customWords match, got {converse_custom_words!r}"
    )
    converse_match = converse_custom_words[0]["match"]
    converse_action = converse_custom_words[0]["action"]

    assert apply_match == converse_match, (
        f"expected ApplyGuardrail match {apply_match!r} to equal Converse match {converse_match!r}"
    )
    assert apply_action == converse_action == "BLOCKED", (
        f"expected both ApplyGuardrail action {apply_action!r} and Converse action "
        f"{converse_action!r} to be BLOCKED"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
