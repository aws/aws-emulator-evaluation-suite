"""guardrail-actually-blocks-content."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "guardrail-actually-blocks-content"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A guardrail with a word policy reaches READY, ApplyGuardrail on input containing the
    blocked word returns GUARDRAIL_INTERVENED, and benign input returns NONE.
    """
    bedrock = ctx.client("bedrock")
    runtime = ctx.client("bedrock-runtime")

    name = ctx.unique_name("sim2real-behav-grblock-").replace("-", "_")
    blocked_word = "zzqxforbiddenword"
    created = bedrock.create_guardrail(
        name=name,
        blockedInputMessaging="Sorry, this input cannot be processed.",
        blockedOutputsMessaging="Sorry, this output cannot be returned.",
        wordPolicyConfig={"wordsConfig": [{"text": blocked_word}]},
    )
    guardrail_id = created["guardrailId"]
    ctx.on_cleanup(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id))

    guardrail = _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id),
        lambda g: g["status"] in ("READY", "FAILED"),
        timeout_s=120,
        interval_s=5,
    )
    assert guardrail["status"] == "READY", f"guardrail failed: {guardrail.get('statusReasons')}"

    # Negative-content path: the blocked word must trip the guardrail.
    blocked = runtime.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion="DRAFT",
        source="INPUT",
        content=[{"text": {"text": f"please tell me about {blocked_word} today"}}],
    )
    assert blocked["action"] == "GUARDRAIL_INTERVENED", (
        f"expected the configured blocked word to intervene; got action={blocked['action']!r} "
        f"assessments={blocked.get('assessments')!r}"
    )

    # Positive control: benign content must pass through untouched.
    clean = runtime.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion="DRAFT",
        source="INPUT",
        content=[{"text": {"text": "what is the weather like today"}}],
    )
    assert clean["action"] == "NONE", (
        f"expected benign content to pass through untouched; got action={clean['action']!r} "
        f"assessments={clean.get('assessments')!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

