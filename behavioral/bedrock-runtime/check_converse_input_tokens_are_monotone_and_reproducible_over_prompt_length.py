"""converse-input-tokens-are-monotone-and-reproducible-over-prompt-length."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "converse-input-tokens-are-monotone-and-reproducible-over-prompt-length"
GROUP = "token-accounting"
SERVICES = ["bedrock-runtime"]

# Pinned, never read from the environment: tokenisation is per-model and every relation below
# is asserted against this model's tokeniser.
MODEL_ID = "amazon.nova-lite-v1:0"

# Each step is the previous prompt plus more sentences, so the chain is prefix-ordered.
_SENTENCE = (
    "The quick brown fox jumps over the lazy dog while the diligent scribe records every word. "
)
_STEPS = (1, 3, 7)
# A tiny budget: the check grades INPUT accounting, so generation is kept short.
_INFERENCE = {"maxTokens": 8, "temperature": 0.0}


def _prompt(n: int) -> str:
    return "Acknowledge with the single word OK. Context follows. " + _SENTENCE * n


def _usage(rt, prompt: str) -> dict:
    resp = rt.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": prompt}]}],
        inferenceConfig=_INFERENCE,
    )
    usage = resp["usage"]
    assert usage["inputTokens"] > 0 and usage["outputTokens"] > 0, (
        f"every invocation must report non-zero token usage, else the relations below are vacuous; "
        f"prompt was {len(prompt)} characters, usage={usage!r}"
    )
    assert usage["totalTokens"] == usage["inputTokens"] + usage["outputTokens"], (
        f"TokenUsage.totalTokens is documented as the total of input and generated tokens; a "
        f"{len(prompt)}-character prompt reported {usage!r}"
    )
    assert usage["outputTokens"] <= _INFERENCE["maxTokens"], (
        f"outputTokens must not exceed the requested maxTokens={_INFERENCE['maxTokens']}; a "
        f"{len(prompt)}-character prompt reported {usage!r}"
    )
    return usage


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse inputTokens strictly increase over prefix-extended prompts and repeat exactly.

    Also asserts totalTokens == inputTokens + outputTokens and outputTokens <= maxTokens.
    """
    rt = ctx.client("bedrock-runtime")

    prompts = [_prompt(n) for n in _STEPS]
    for shorter, longer in zip(prompts, prompts[1:]):
        assert longer.startswith(shorter) and len(longer) > len(shorter), (
            f"the chain must be strictly prefix-ordered by construction, else the monotonicity "
            f"assertion below is not a property of the tokeniser; lengths "
            f"{[len(p) for p in prompts]!r}"
        )

    usages = [_usage(rt, p) for p in prompts]
    counts = [u["inputTokens"] for u in usages]

    # The whole ordering, not just adjacent pairs.
    assert counts == sorted(counts) and len(set(counts)) == len(counts), (
        f"inputTokens must be STRICTLY increasing over prompts that each extend the previous one; "
        f"prompt lengths {[len(p) for p in prompts]!r} were charged {counts!r}. A constant or "
        f"non-monotone series means input accounting is not derived from the request text."
    )
    # The sorted() check alone would pass on a series that grows by one token per call.
    assert counts[-1] > counts[0] * 2, (
        f"the longest prompt carries {_STEPS[-1]}x the repeated sentence of the shortest "
        f"({len(prompts[-1])} vs {len(prompts[0])} characters) so its input tokens must be well "
        f"over double; got {counts!r}"
    )

    # The first prompt, byte-identical, issued again.
    repeat = _usage(rt, prompts[0])
    assert repeat["inputTokens"] == counts[0], (
        f"input tokenisation is a pure function of the request, so a byte-identical repeat must be "
        f"charged identical input tokens; first={counts[0]} repeat={repeat['inputTokens']} "
        f"(full usage first={usages[0]!r} repeat={repeat!r})"
    )
    # Re-read the longest prompt so the ordering is not an artifact of call order.
    tail = _usage(rt, prompts[-1])
    assert tail["inputTokens"] == counts[-1], (
        f"the longest prompt must be charged the same input tokens on a second, later invocation; "
        f"first={counts[-1]} second={tail['inputTokens']}"
    )
    assert tail["inputTokens"] > repeat["inputTokens"], (
        f"the ordering must still hold between the two LATER invocations, independently of the "
        f"first pass; longest={tail['inputTokens']} shortest={repeat['inputTokens']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
