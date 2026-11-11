"""apply-guardrail-word-filter-state-transition."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apply-guardrail-word-filter-state-transition"
GROUP = "state"
SERVICES = ["bedrock-runtime"]

BLOCKED_WORD = "FLIBBERTIGIBBET"
BLOCKED_MESSAGE = "Blocked by test guardrail."

#: Bounded wait for a guardrail to reach a terminal status (the default service-class budget).
POLL_DEADLINE_S = 600.0


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ApplyGuardrail intervenes (GUARDRAIL_INTERVENED, with a wordPolicy match) on content
    containing the configured blocked word, and passes through clean content unmodified (NONE);
    once the guardrail is deleted it is not-found, unlisted, and ApplyGuardrail is refused."""
    guardrail_id = _create_word_guardrail(ctx, BLOCKED_WORD)
    brt = ctx.client("bedrock-runtime")

    blocked = brt.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion="DRAFT",
        source="INPUT",
        content=[{"text": {"text": f"I really enjoy saying {BLOCKED_WORD} out loud."}}],
    )
    assert blocked["action"] == "GUARDRAIL_INTERVENED", (
        f"expected action=GUARDRAIL_INTERVENED for content containing the configured word "
        f"{BLOCKED_WORD!r}; got {blocked['action']!r}"
    )
    blocked_texts = [o["text"] for o in blocked["outputs"]]
    assert blocked_texts == [BLOCKED_MESSAGE], (
        f"expected the intervened outputs to be the configured blockedInputMessaging "
        f"{BLOCKED_MESSAGE!r}; got {blocked_texts!r}"
    )
    blocked_hits = [
        w
        for a in blocked["assessments"]
        for w in a.get("wordPolicy", {}).get("customWords", [])
        if w.get("match") == BLOCKED_WORD
    ]
    assert blocked_hits and all(w.get("action") == "BLOCKED" for w in blocked_hits), (
        f"expected a wordPolicy.customWords entry for {BLOCKED_WORD!r} with action=BLOCKED; "
        f"got {blocked['assessments']!r}"
    )

    allowed = brt.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion="DRAFT",
        source="INPUT",
        content=[{"text": {"text": "I really enjoy eating mango smoothies."}}],
    )
    assert allowed["action"] == "NONE", (
        f"expected action=NONE for content with no configured word; got {allowed['action']!r}"
    )
    allowed_blocked = [
        w
        for a in allowed["assessments"]
        for w in a.get("wordPolicy", {}).get("customWords", [])
        if w.get("action") == "BLOCKED"
    ]
    assert not allowed_blocked, (
        f"clean content must report no BLOCKED wordPolicy entries; got {allowed['assessments']!r}"
    )

    bedrock = ctx.client("bedrock")
    assert guardrail_id in _listed_ids(bedrock), "the live guardrail must be listed before the delete"
    bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)

    deadline = time.monotonic() + POLL_DEADLINE_S
    while True:
        try:
            bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
        except ClientError as exc:
            gone_code, gone_status, gone_message = _error_tuple(exc)
            break
        if time.monotonic() >= deadline:
            raise AssertionError("GetGuardrail still answers for the deleted guardrail")
        time.sleep(2)
    assert (gone_code, gone_status) == ("ResourceNotFoundException", 404), (
        f"GetGuardrail on the deleted guardrail: expected ResourceNotFoundException/404, got {gone_code}/{gone_status}"
    )
    expected_message = "This guardrail does not exist."
    assert gone_message == expected_message, f"expected the message {expected_message!r}, got {gone_message!r}"

    assert guardrail_id not in _listed_ids(bedrock), "the deleted guardrail is still listed"

    try:
        result = brt.apply_guardrail(
            guardrailIdentifier=guardrail_id,
            guardrailVersion="DRAFT",
            source="INPUT",
            content=[{"text": {"text": f"I really enjoy saying {BLOCKED_WORD} out loud."}}],
        )
    except ClientError as exc:
        dead_code, dead_status, dead_message = _error_tuple(exc)
    else:
        raise AssertionError(f"ApplyGuardrail on the deleted guardrail SUCCEEDED: {result.get('action')!r}")
    # AWS answers an ApplyGuardrail on an identifier that does not resolve with a 400
    # ValidationException.
    assert (dead_code, dead_status) == ("ValidationException", 400), (
        f"ApplyGuardrail on the deleted guardrail: expected ValidationException/400, got {dead_code}/{dead_status}"
    )
    expected_message = "The guardrail identifier or version provided in the request does not exist."
    assert dead_message == expected_message, f"expected the message {expected_message!r}, got {dead_message!r}"


def _error_tuple(exc: ClientError) -> tuple[str, int, str]:
    return (exc.response["Error"]["Code"], exc.response["ResponseMetadata"]["HTTPStatusCode"],
            exc.response["Error"].get("Message", ""))


def _listed_ids(bedrock: Any) -> set[str]:
    """Every guardrail id ListGuardrails returns, following nextToken."""
    ids, kwargs = set(), {}
    while True:
        page = bedrock.list_guardrails(**kwargs)
        ids.update(g["id"] for g in page["guardrails"])
        if not page.get("nextToken"):
            return ids
        kwargs["nextToken"] = page["nextToken"]


def _delete_if_present(bedrock: Any, guardrail_id: str) -> None:
    """Teardown: delete the guardrail unless the body already deleted it."""
    try:
        bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_word_guardrail(ctx: Any, blocked_word: str) -> str:
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-behav-grd-")
    created = bedrock.create_guardrail(
        name=name,
        blockedInputMessaging=BLOCKED_MESSAGE,
        blockedOutputsMessaging="Blocked by test guardrail.",
        wordPolicyConfig={"wordsConfig": [{"text": blocked_word}]},
        tags=[{"key": "sim2real:managed", "value": "true"}],
    )
    guardrail_id = created["guardrailId"]
    ctx.on_cleanup(lambda: _delete_if_present(bedrock, guardrail_id))
    deadline = time.monotonic() + POLL_DEADLINE_S
    while True:
        status = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion="DRAFT")["status"]
        if status == "READY":
            return guardrail_id
        if status == "FAILED":
            raise AssertionError("guardrail creation reported status FAILED")
        if time.monotonic() >= deadline:
            raise AssertionError(f"guardrail never reached a terminal status (last {status!r})")
        time.sleep(1)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
