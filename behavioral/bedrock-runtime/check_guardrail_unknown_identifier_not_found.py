"""guardrail-unknown-identifier-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "guardrail-unknown-identifier-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-runtime"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ApplyGuardrail on a well-formed ARN for a guardrail that was never created is rejected with
    ValidationException and its exact message, while the same call on a freshly created guardrail
    succeeds with action NONE."""
    client = ctx.client("bedrock-runtime")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:bedrock:{ctx.region}:{account_id}:guardrail/abcdef123456"
    content = [{"text": {"text": "Is this content safe?"}}]

    code, message = _error(
        lambda: client.apply_guardrail(
            guardrailIdentifier=bogus_arn,
            guardrailVersion="DRAFT",
            source="INPUT",
            content=content,
        )
    )
    assert code == "ValidationException", f"got {code!r}"
    assert message == 'The guardrail identifier or version provided in the request does not exist.', f"unexpected refusal message {message!r}"
    assert code not in ("InternalServerException", "ServiceUnavailableException")

    guardrail_id = _create_word_guardrail(ctx, "FLIBBERTIGIBBET")
    control = client.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion="DRAFT",
        source="INPUT",
        content=content,
    )
    assert control["action"] == "NONE", f"got {control['action']!r}"

    # Rules out a broken client/region setup as the cause of the rejection above.
    convo = client.converse(
        modelId=_pick_converse_model(client),
        messages=[{"role": "user", "content": [{"text": "Say the word 'pong' and nothing else."}]}],
    )
    assert "output" in convo and "message" in convo["output"]


_CONVERSE_MODEL_CANDIDATES = [
    "amazon.nova-lite-v1:0",
    "amazon.nova-micro-v1:0",
    "anthropic.claude-3-5-haiku-20241022-v1:0",
    "amazon.titan-text-express-v1",
]


def _create_word_guardrail(ctx, blocked_word: str) -> str:
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-behav-grd-")
    created = bedrock.create_guardrail(
        name=name,
        blockedInputMessaging="Blocked by test guardrail.",
        blockedOutputsMessaging="Blocked by test guardrail.",
        wordPolicyConfig={"wordsConfig": [{"text": blocked_word}]},
        tags=[{"key": "sim2real", "value": CHECK}],
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


def _pick_converse_model(client):
    from botocore.exceptions import ClientError

    last_exc = None
    for candidate in _CONVERSE_MODEL_CANDIDATES:
        try:
            client.converse(
                modelId=candidate,
                messages=[{"role": "user", "content": [{"text": "ping"}]}],
                inferenceConfig={"maxTokens": 5},
            )
            return candidate
        except ClientError as exc:
            last_exc = exc
            continue
    raise AssertionError(
        f"no candidate Converse model is invokable in this account/region; last error: {last_exc}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected ApplyGuardrail to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
