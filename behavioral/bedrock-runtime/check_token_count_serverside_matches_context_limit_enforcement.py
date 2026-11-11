"""token-count-serverside-matches-context-limit-enforcement."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "token-count-serverside-matches-context-limit-enforcement"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]

# Invokable models that CountTokens refuses as unsupported. amazon.nova-micro-v1:0 is only
# reachable through its cross-region inference profile id; nova-lite works by its bare id.
_CANDIDATE_MODELS = [
    "amazon.nova-lite-v1:0",
    "us.amazon.nova-micro-v1:0",
]
_MESSAGES = [{"role": "user", "content": [{"text": "Say hello."}]}]


def _error_code_and_message(fn):
    """Return (code, message) for a refused call; raise if it unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected CountTokens to be refused but it SUCCEEDED, response={resp!r}")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """For each candidate, Converse proves the model is invocable and CountTokens still refuses it
    with the same specific ValidationException, not a generic or model-varying failure."""
    bedrock = ctx.client("bedrock-runtime")

    for model_id in _CANDIDATE_MODELS:
        # Positive control: rules out an unreachable model as the cause of the refusal.
        control = bedrock.converse(modelId=model_id, messages=_MESSAGES, inferenceConfig={"maxTokens": 8})
        assert control["output"]["message"]["content"][0]["text"].strip() != "", (
            f"positive control: Converse against {model_id!r} produced no text, so this "
            "model's liveness is not established"
        )

        def _count_tokens():
            return bedrock.count_tokens(modelId=model_id, input={"converse": {"messages": _MESSAGES}})

        code, message = _error_code_and_message(_count_tokens)
        assert code == "ValidationException", (
            f"expected CountTokens to refuse {model_id!r} with ValidationException, "
            f"got {code!r} (message={message!r})"
        )
        assert message == "The provided model doesn't support counting tokens.", (
            f"expected the specific unsupported-capability refusal for {model_id!r}, "
            f"got message={message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
