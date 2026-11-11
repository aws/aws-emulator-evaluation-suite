"""converse-stop-reason-switches-on-the-budget-not-on-the-prompt."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "converse-stop-reason-switches-on-the-budget-not-on-the-prompt"
GROUP = "state"
SERVICES = ["bedrock-runtime"]

# Pinned: the budget-to-stopReason relation is graded against this model's generation behaviour.
MODEL_ID = "amazon.nova-lite-v1:0"

# Byte-identical across both arms. Long enough that a 5-token budget cannot satisfy it.
_PROMPT = "Write a detailed 500 word essay about the history of Rome."
_TINY = 5
_GENEROUS = 2048
_TEMPERATURE = 0.0


def _text(resp) -> str:
    return "".join(b.get("text", "") for b in resp["output"]["message"]["content"])


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """For a byte-identical prompt, stopReason is max_tokens under a tiny budget (spending it exactly)
    and end_turn under a generous one, with identical input tokens, so it depends on the budget.

    Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html
    """
    rt = ctx.client("bedrock-runtime")
    messages = [{"role": "user", "content": [{"text": _PROMPT}]}]

    def call(max_tokens: int):
        return rt.converse(
            modelId=MODEL_ID,
            messages=messages,
            inferenceConfig={"maxTokens": max_tokens, "temperature": _TEMPERATURE},
        )

    # Tiny budget: generation must be cut off by the budget.
    tiny = call(_TINY)
    tiny_usage = tiny["usage"]
    assert tiny["stopReason"] == "max_tokens", (
        f"a maxTokens={_TINY} budget on a prompt that asks for a 500-word essay must truncate; got "
        f"stopReason={tiny['stopReason']!r} usage={tiny_usage!r} text={_text(tiny)!r}"
    )
    # Equality, not <=: a target that generates nothing would also satisfy <=.
    assert tiny_usage["outputTokens"] == _TINY, (
        f"a run that reports max_tokens spent its whole budget, so outputTokens must equal the "
        f"requested maxTokens={_TINY} exactly; got {tiny_usage['outputTokens']} "
        f"(usage={tiny_usage!r}). `<= {_TINY}` is also what a target that generates nothing "
        f"produces, which is why this is an equality."
    )
    assert _text(tiny).strip(), (
        f"a truncated response must still carry the tokens it did generate; got {_text(tiny)!r}"
    )
    assert tiny_usage["totalTokens"] == tiny_usage["inputTokens"] + tiny_usage["outputTokens"], (
        f"TokenUsage.totalTokens is the total of input and generated tokens; the truncated arm "
        f"reported {tiny_usage!r}"
    )

    # Same prompt, only the budget changed.
    generous = call(_GENEROUS)
    generous_usage = generous["usage"]
    assert generous["stopReason"] == "end_turn", (
        f"the identical prompt under a maxTokens={_GENEROUS} budget must finish on its own, so "
        f"stopReason is a function of the BUDGET and not of the prompt text; got "
        f"stopReason={generous['stopReason']!r} usage={generous_usage!r}"
    )
    assert generous_usage["outputTokens"] < _GENEROUS, (
        f"the untruncated arm must have finished strictly inside its budget, else it is testing "
        f"truncation too; outputTokens={generous_usage['outputTokens']} budget={_GENEROUS}"
    )
    assert generous_usage["outputTokens"] > _TINY, (
        f"the untruncated arm must have generated more than the truncated arm's whole budget, else "
        f"the two arms are not distinguishable by output length; "
        f"generous={generous_usage['outputTokens']} tiny budget={_TINY}"
    )
    assert (generous_usage["totalTokens"]
            == generous_usage["inputTokens"] + generous_usage["outputTokens"]), (
        f"TokenUsage.totalTokens is the total of input and generated tokens; the untruncated arm "
        f"reported {generous_usage!r}"
    )

    # maxTokens is not model input, so both arms are charged identical input tokens.
    assert generous_usage["inputTokens"] == tiny_usage["inputTokens"], (
        f"maxTokens is a generation budget, not part of the model's input, so a byte-identical "
        f"prompt must be charged identical input tokens under both budgets; "
        f"tiny={tiny_usage!r} generous={generous_usage!r}"
    )
    assert generous_usage["outputTokens"] > tiny_usage["outputTokens"], (
        f"raising the budget must let more tokens be generated for the same prompt; "
        f"tiny={tiny_usage['outputTokens']} generous={generous_usage['outputTokens']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
