"""bedrock-runtime-prompt-cache-point-reuses-input-tokens-across-calls."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "bedrock-runtime-prompt-cache-point-reuses-input-tokens-across-calls"
GROUP = 'token-accounting'
SERVICES = ['bedrock-runtime']

# Prompt caching is per-model: this model writes then reads back the prefix, while
# us.amazon.nova-pro-v1:0 writes on every call and never reports a read.
MODEL_ID = "amazon.nova-lite-v1:0"

_SUFFIX = "Reply with the single word ALPHA."
_INFERENCE = {"maxTokens": 16, "temperature": 0.0}
#: ~42k tokens, well above this model's minimum cacheable prefix.
_FILLER_SECTIONS = 1200
#: Caching is best effort: AWS occasionally ignores a cachePoint (about 1 call in 6) and bills the
#: prefix as inputTokens. Five fresh attempts tolerate that while a target that never caches fails.
_CACHE_ATTEMPTS = 5


def _prefix(nonce: str) -> str:
    """A long prefix unique to this run and attempt.

    The server-side cache outlives the check, so a constant prefix would already be warm
    on the cold call.
    """
    return " ".join(
        f"section{i} of dossier {nonce}: the quick brown fox jumps over the lazy dog number {i}."
        for i in range(_FILLER_SECTIONS)
    )


def _assert_total_closes(label, usage):
    """totalTokens equals input + output + cache read + cache write, cached or not."""
    expected = (usage["inputTokens"] + usage["outputTokens"]
                + usage.get("cacheReadInputTokens", 0)
                + usage.get("cacheWriteInputTokens", 0))
    assert usage["totalTokens"] == expected, (
        f"totalTokens must account for the cache tokens as well as inputTokens and outputTokens "
        f"on the {label} call; usage={usage!r} expected {expected}"
    )


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A cachePoint makes a replay read back exactly the tokens the cold call wrote, inputTokens
    counts only the suffix, and a prefix differing in its first token does not hit the cache.

    Reference: https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-caching.html
    """
    rt = ctx.client("bedrock-runtime")

    def converse(prefix):
        return rt.converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [
                {"text": prefix},
                {"cachePoint": {"type": "default"}},
                {"text": _SUFFIX},
            ]}],
            inferenceConfig=_INFERENCE,
        )["usage"]

    # Find an attempt on which the service actually took the cache. Every attempt uses a FRESH
    # prefix, so no attempt can be warmed by an earlier one, and the arithmetic invariant is
    # asserted on every call regardless of the outcome.
    prefix = cold = warm = None
    misses = []
    for _ in range(_CACHE_ATTEMPTS):
        prefix = _prefix(ctx.unique_name("dossier-"))
        cold = converse(prefix)
        _assert_total_closes("cold", cold)
        assert cold.get("cacheReadInputTokens", 0) == 0, (
            f"a prefix never sent before cannot be read from the cache; usage={cold!r}"
        )
        if cold.get("cacheWriteInputTokens", 0) > 0:
            warm = converse(prefix)
            _assert_total_closes("warm", warm)
            break
        # The cachePoint was ignored: the prefix was billed as ordinary input instead of cached.
        assert cold["inputTokens"] > 1000, (
            f"the cachePoint was not honoured, so the whole prefix must be billed as ordinary "
            f"input tokens -- a call that cached nothing AND billed nothing for the prefix has "
            f"lost it; usage={cold!r}"
        )
        misses.append(cold)
        cold = None

    assert cold is not None, (
        f"the service never cached a prefix in {_CACHE_ATTEMPTS} attempts, each over a "
        f"{_FILLER_SECTIONS}-section prefix well above this model's minimum. Real AWS missed 1 of "
        f"6 measured attempts, so {_CACHE_ATTEMPTS} consecutive misses means cachePoint is being "
        f"accepted and ignored; per-attempt usage was {misses!r}"
    )
    written = cold["cacheWriteInputTokens"]

    assert warm.get("cacheReadInputTokens", 0) == written, (
        f"a byte-identical replay must read back exactly what the cold call wrote; wrote "
        f"{written} read {warm.get('cacheReadInputTokens', 0)} usage={warm!r}"
    )
    assert warm.get("cacheWriteInputTokens", 0) == 0, (
        f"a cache hit must not rewrite the prefix it just read; usage={warm!r}"
    )

    # The tokens before the cachePoint are accounted as cache tokens and NOT as inputTokens, so
    # inputTokens counts only the suffix -- identical on both calls, and small. This is the
    # assertion an emulator that folds the cached prefix back into inputTokens fails.
    assert warm["inputTokens"] == cold["inputTokens"], (
        f"inputTokens counts only the content AFTER the cachePoint, so it cannot change between a "
        f"cold call and its replay; cold={cold!r} warm={warm!r}"
    )
    assert cold["inputTokens"] < written, (
        f"the cached prefix is much larger than the uncached suffix, so inputTokens must be far "
        f"below the cached token count; inputTokens={cold['inputTokens']} cached={written}"
    )

    # Control: a prefix that diverges in its FIRST token shares no cacheable prefix, so it must
    # miss. It is asserted as a miss only -- whether the service then caches IT is the same
    # best-effort decision measured above, so requiring that would reintroduce the flake.
    diverged = converse("PREAMBLE " + prefix)
    _assert_total_closes("diverged", diverged)
    assert diverged.get("cacheReadInputTokens", 0) == 0, (
        f"a prefix that differs from the cached one in its FIRST token must not hit the cache; "
        f"usage={diverged!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
