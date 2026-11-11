"""optimize-prompt-invalid-model-reference-validation-exception."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "optimize-prompt-invalid-model-reference-validation-exception"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent-runtime"]

# Supported prompt-optimization target models (Bedrock user guide, "Supported Regions and models
# for prompt optimization"), tried in order since per-account model access varies; any one
# succeeding proves the happy path before the invalid-model-reference probes below.
_CANDIDATE_TARGET_MODEL_IDS = [
    "anthropic.claude-haiku-4-5-20251001-v1:0",
    "anthropic.claude-sonnet-4-20250514-v1:0",
    "anthropic.claude-sonnet-4-5-20250929-v1:0",
]
_OTHER_REGION = "eu-central-1"


@tags("axis:rejection", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """OptimizePrompt succeeds against a supported target model, while a foundation-model ARN in
    another Region and a nonexistent provisioned-model ARN are both rejected at request validation
    with ValidationException, not a dependency or 5xx-shaped error."""
    client = ctx.client("bedrock-agent-runtime")

    events = None
    last_err = None
    for model_id in _CANDIDATE_TARGET_MODEL_IDS:
        try:
            events = _drain_optimize_prompt(
                client,
                input={"textPrompt": {"text": "Please summarize this text: "}},
                targetModelId=model_id,
            )
            break
        except ClientError as err:
            last_err = err
            continue
    assert events is not None, f"no candidate target model was usable in this account: {last_err}"
    assert any("optimizedPromptEvent" in e or "analyzePromptEvent" in e for e in events), (
        f"expected an optimizedPromptEvent/analyzePromptEvent in the stream, got: {events!r}"
    )
    assert not any(k.endswith("Exception") for e in events for k in e), (
        f"expected no *Exception event in the positive-control stream, got: {events!r}"
    )

    # Syntactically valid per the targetModelId pattern (foundation-model ARN shape,
    # cross-region) referencing a real foundation model but in a Region where this caller's
    # OptimizePrompt request cannot reach it -- an unreachable model dependency, not a
    # malformed request -- yet AWS classifies it as ValidationException.
    cross_region_foundation_model_arn = (
        f"arn:aws:bedrock:{_OTHER_REGION}::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0"
    )
    code, message = _error(
        lambda: _drain_optimize_prompt(
            client,
            input={"textPrompt": {"text": "Please summarize this text: "}},
            targetModelId=cross_region_foundation_model_arn,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Invalid ARN format: Incorrect region/partition.", (
        f"expected message 'Invalid ARN format: Incorrect region/partition.', got {message!r}"
    )

    # Same conclusion holds for a syntactically valid but nonexistent provisioned-model ARN
    # in-Region -- reinforcing that OptimizePrompt does not distinguish "malformed" from
    # "unreachable" model references; both are ValidationException, never DependencyFailed.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_provisioned_model_arn = (
        f"arn:aws:bedrock:{ctx.region}:{account_id}:provisioned-model/aaaaaaaaaaaa"
    )
    code2, message2 = _error(
        lambda: _drain_optimize_prompt(
            client,
            input={"textPrompt": {"text": "Please summarize this text: "}},
            targetModelId=bogus_provisioned_model_arn,
        )
    )
    assert code2 == "ValidationException", f"expected ValidationException, got {code2!r}"
    expected_message2 = (
        "Input validation failed. Check your request parameters and retry the request. "
        "Invalid model ID: The provided model identifier is invalid."
    )
    assert message2 == expected_message2, (
        f"expected message {expected_message2!r}, got {message2!r}"
    )



# ===== helpers =====

def _drain_optimize_prompt(client, **kwargs):
    response = client.optimize_prompt(**kwargs)
    events = []
    for event in response["optimizedPrompt"]:
        events.append(event)
    return events


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, because
    accepting a model reference AWS refuses is a failure in its own right, not a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
