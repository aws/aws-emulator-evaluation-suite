"""bedrock-max-tokens-truncation-reports-stop-reason-max-tokens."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "bedrock-max-tokens-truncation-reports-stop-reason-max-tokens"
GROUP = 'converse'
SERVICES = ['bedrock']

# The exact stop reasons below are per-model behavior, so the model is pinned;
# amazon.nova-lite-v1:0 is ON_DEMAND (no inference profile, no provider use-case form).
MODEL_ID = "amazon.nova-lite-v1:0"

# A prompt with a definite, short, complete answer: it must FINISH inside the uncapped budget so
# the uncapped leg can assert 'end_turn' exactly.
_PROMPT = "List the integers from 1 to 12 separated by commas. Output nothing else."


def _converse(rt, max_tokens):
    return rt.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": _PROMPT}]}],
        inferenceConfig={"maxTokens": max_tokens, "temperature": 0.0},
    )


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """Converse with maxTokens=1 stops with 'max_tokens' and outputTokens 1, the same prompt with
    maxTokens=512 stops with 'end_turn' and more tokens, and on both legs totalTokens is the sum
    of equal inputTokens and outputTokens: the cap alone causes the truncation.
    """
    rt = ctx.client("bedrock-runtime")

    capped = _converse(rt, 1)
    assert capped["stopReason"] == "max_tokens", (
        f"maxTokens=1 must stop with 'max_tokens'; got {capped['stopReason']!r} "
        f"usage={capped['usage']!r}"
    )
    assert capped["usage"]["outputTokens"] == 1, (
        f"maxTokens=1 must bill exactly one output token, not merely 'few'; "
        f"usage={capped['usage']!r}"
    )

    uncapped = _converse(rt, 512)
    assert uncapped["stopReason"] == "end_turn", (
        f"the same prompt with a budget it fits inside must stop with 'end_turn'; got "
        f"{uncapped['stopReason']!r} usage={uncapped['usage']!r}"
    )
    assert uncapped["usage"]["outputTokens"] > 1, (
        f"the uncapped leg must generate more than the single capped token, otherwise the cap "
        f"above explains nothing; usage={uncapped['usage']!r}"
    )

    # The service's own arithmetic, on both legs. An emulator that fabricates usage numbers
    # independently of each other fails here even when both stop reasons are right.
    for label, resp in (("capped", capped), ("uncapped", uncapped)):
        usage = resp["usage"]
        assert usage["totalTokens"] == usage["inputTokens"] + usage["outputTokens"], (
            f"{label} leg: totalTokens must equal inputTokens + outputTokens; usage={usage!r}"
        )

    # The input side is identical across the two legs -- only the output budget differed.
    assert capped["usage"]["inputTokens"] == uncapped["usage"]["inputTokens"], (
        f"the two legs sent byte-identical messages, so inputTokens must agree; "
        f"capped={capped['usage']!r} uncapped={uncapped['usage']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
