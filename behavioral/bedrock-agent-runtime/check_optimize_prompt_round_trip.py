"""optimize-prompt-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "optimize-prompt-round-trip"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]

_ERROR_EVENT_KEYS = (
    "validationException",
    "accessDeniedException",
    "badGatewayException",
    "dependencyFailedException",
    "internalServerException",
    "throttlingException",
)

# OptimizePrompt rejects an inference-profile id/ARN as targetModelId with ValidationException
# ("Invalid model ID"), so candidates are models listed ON_DEMAND, tried in order because
# on-demand availability varies by account and region.
_CANDIDATE_TARGET_MODEL_IDS = [
    "amazon.nova-lite-v1:0",
    "meta.llama3-1-70b-instruct-v1:0",
    "mistral.mistral-large-2407-v1:0",
]


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """OptimizePrompt streams back a non-empty, error-free optimized prompt that differs from the
    input, and feeding that output back into OptimizePrompt yields a second non-empty, error-free
    optimized result rather than a rejection."""
    client = ctx.client("bedrock-agent-runtime")
    original_text = "Write a one-sentence summary of what an ocean is."

    model_id, optimized_text = _optimize_with_any_candidate(client, original_text)
    assert optimized_text.strip() != "", "OptimizePrompt returned no optimized text content"
    assert optimized_text.strip() != original_text.strip(), (
        f"OptimizePrompt echoed the input unchanged instead of optimizing it: {optimized_text!r}"
    )

    round_tripped_text = _optimize(client, optimized_text, model_id)
    assert round_tripped_text.strip() != "", (
        "OptimizePrompt rejected its own prior output as input on round-trip "
        f"(re-optimizing {optimized_text!r} returned no content)"
    )


def _optimize_with_any_candidate(client, text_prompt: str) -> tuple[str, str]:
    last_err: ClientError | None = None
    for model_id in _CANDIDATE_TARGET_MODEL_IDS:
        try:
            return model_id, _optimize(client, text_prompt, model_id)
        except ClientError as err:
            last_err = err
            continue
    raise AssertionError(f"no candidate target model was usable in this account: {last_err}")


def _optimize(client, text_prompt: str, model_id: str) -> str:
    response = client.optimize_prompt(
        input={"textPrompt": {"text": text_prompt}},
        targetModelId=model_id,
    )
    text_parts = []
    for event in response["optimizedPrompt"]:
        if "optimizedPromptEvent" in event:
            text_prompt_out = event["optimizedPromptEvent"].get("optimizedPrompt", {}).get("textPrompt")
            if text_prompt_out and text_prompt_out.get("text"):
                text_parts.append(text_prompt_out["text"])
        elif any(key in event for key in _ERROR_EVENT_KEYS):
            raise AssertionError(f"OptimizePrompt stream raised an event error: {event}")
    return "".join(text_parts)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
