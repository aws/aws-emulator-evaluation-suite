"""optimize-prompt-returns-nonempty-result."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "optimize-prompt-returns-nonempty-result"
GROUP = "model-invoke"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """OptimizePrompt streams back at least one optimizedPromptEvent carrying a non-empty
    rewritten prompt for the target model, and the rewrite is a real transformation of the
    input rather than a passthrough echo."""
    client = ctx.client("bedrock-agent-runtime")
    # Supported prompt-optimization target models, tried in order since per-account model
    # access varies; any one succeeding is the target this check exercises.
    candidate_target_model_ids = [
        "anthropic.claude-haiku-4-5-20251001-v1:0",
        "anthropic.claude-sonnet-4-20250514-v1:0",
        "anthropic.claude-sonnet-4-5-20250929-v1:0",
    ]
    original_text = "Write a short summary of what a knowledge base is."

    resp = None
    last_err = None
    for target_model_id in candidate_target_model_ids:
        try:
            resp = client.optimize_prompt(
                input={"textPrompt": {"text": original_text}},
                targetModelId=target_model_id,
            )
            break
        except ClientError as err:
            last_err = err
            continue
    assert resp is not None, f"no candidate target model was usable in this account: {last_err}"

    optimized_texts = []
    for event in resp["optimizedPrompt"]:
        if "optimizedPromptEvent" in event:
            optimized = event["optimizedPromptEvent"].get("optimizedPrompt") or {}
            text_prompt = optimized.get("textPrompt")
            if text_prompt and text_prompt.get("text"):
                optimized_texts.append(text_prompt["text"])
        elif any(
            k in event
            for k in (
                "validationException",
                "accessDeniedException",
                "badGatewayException",
                "dependencyFailedException",
                "internalServerException",
                "throttlingException",
            )
        ):
            raise AssertionError(f"OptimizePrompt stream raised an event error: {event}")

    combined = "".join(optimized_texts)
    assert len(combined) > 0, "no optimized prompt text was streamed back"
    assert combined.strip() != original_text.strip(), (
        f"optimized prompt was an unchanged echo of the input: {combined!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
