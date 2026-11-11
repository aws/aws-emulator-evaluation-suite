"""rerank-scoring-consistency-across-calls."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rerank-scoring-consistency-across-calls"
GROUP = "server-side"
SERVICES = ["bedrock-agent-runtime"]

_MODEL_ARN_TEMPLATE = "arn:aws:bedrock:{region}::foundation-model/amazon.rerank-v1:0"

_QUERY = "What is the capital of France?"
_SOURCES = [
    "Paris is the capital and most populous city of France.",
    "Berlin is the capital of Germany.",
    "The Eiffel Tower is located in Paris, France.",
    "Bananas are a good source of potassium.",
    "Madrid is the capital of Spain.",
]


def _rerank_config(region: str) -> dict:
    return {
        "type": "BEDROCK_RERANKING_MODEL",
        "bedrockRerankingConfiguration": {
            "modelConfiguration": {"modelArn": _MODEL_ARN_TEMPLATE.format(region=region)},
        },
    }


def _do_rerank(client, region: str) -> list[dict]:
    resp = client.rerank(
        queries=[{"type": "TEXT", "textQuery": {"text": _QUERY}}],
        sources=[
            {
                "type": "INLINE",
                "inlineDocumentSource": {"type": "TEXT", "textDocument": {"text": t}},
            }
            for t in _SOURCES
        ],
        rerankingConfiguration=_rerank_config(region),
    )
    return resp["results"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two identical Rerank calls return the same ordering and the exact same relevance scores, with a
    relevant source ranked first."""
    client = ctx.client("bedrock-agent-runtime")

    first = _do_rerank(client, ctx.region)
    second = _do_rerank(client, ctx.region)

    assert len(first) == len(second) == len(_SOURCES), (
        f"expected {len(_SOURCES)} reranked results from both calls, "
        f"got {len(first)} then {len(second)}"
    )

    first_order = [r["index"] for r in first]
    second_order = [r["index"] for r in second]
    assert first_order == second_order, (
        f"reranked document order changed between identical calls: {first_order} != {second_order}"
    )

    first_scores = {r["index"]: r["relevanceScore"] for r in first}
    second_scores = {r["index"]: r["relevanceScore"] for r in second}
    assert first_scores == second_scores, (
        f"relevance scores changed between identical calls: {first_scores} != {second_scores}"
    )

    # Sanity: the ranking must actually be relevance-driven, not a no-op --
    # the top match should be a Paris/France document (index 0 or 2), not the
    # unrelated banana document (index 3).
    assert first_order[0] in (0, 2), f"top-ranked result was not relevant: {first}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
