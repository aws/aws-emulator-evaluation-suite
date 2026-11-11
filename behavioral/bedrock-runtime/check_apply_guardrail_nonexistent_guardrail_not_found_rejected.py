"""apply-guardrail-nonexistent-guardrail-not-found-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apply-guardrail-nonexistent-guardrail-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]

FAKE_GUARDRAIL_ID = "aaaaaaaaaaaa"  # syntactically-valid 12-char guardrail id, never created


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ApplyGuardrail on a well-formed but nonexistent guardrail id fails with ValidationException.

    The same call against a freshly created guardrail succeeds with action NONE."""
    brt = ctx.client("bedrock-runtime")

    code, message = _error(
        lambda: brt.apply_guardrail(
            guardrailIdentifier=FAKE_GUARDRAIL_ID,
            guardrailVersion="DRAFT",
            source="INPUT",
            content=[{"text": {"text": "hello there"}}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == 'The guardrail identifier or version provided in the request does not exist.', f"unexpected refusal message {message!r}"

    guardrail_id = _create_word_guardrail(ctx, "FLIBBERTIGIBBET")
    control = brt.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion="DRAFT",
        source="INPUT",
        content=[{"text": {"text": "hello there"}}],
    )
    assert control["action"] == "NONE", f"expected action NONE, got {control['action']!r}"


def _create_word_guardrail(ctx: Any, blocked_word: str) -> str:
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-behav-grd-")
    created = bedrock.create_guardrail(
        name=name,
        blockedInputMessaging="Blocked by test guardrail.",
        blockedOutputsMessaging="Blocked by test guardrail.",
        wordPolicyConfig={"wordsConfig": [{"text": blocked_word}]},
        tags=[{"key": "sim2real", "value": CHECK}, {"key": "sim2real:managed", "value": "true"}],
    )
    guardrail_id = created["guardrailId"]
    ctx.on_cleanup(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion="DRAFT")["status"]
        if status == "READY":
            return guardrail_id
        if status == "FAILED":
            raise AssertionError("guardrail creation reported status FAILED")
        time.sleep(1)
    raise AssertionError("guardrail never reached READY status within 30s")


def _error(fn):
    """Return (code, message) of the ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ApplyGuardrail to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
