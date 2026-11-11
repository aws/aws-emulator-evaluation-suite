"""rerank-orders-sources-by-relevance."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "rerank-orders-sources-by-relevance"
GROUP = "model-invoke"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Rerank of one relevant and one irrelevant source returns 2 results in descending relevanceScore
    order, with the relevant source (index 1) first."""
    client = ctx.client("bedrock-agent-runtime")
    model_arn = f"arn:aws:bedrock:{ctx.region}::foundation-model/amazon.rerank-v1:0"

    relevant_text = "Paris is the capital city of France."
    irrelevant_text = "Bananas are an excellent source of potassium."

    resp = client.rerank(
        queries=[
            {"type": "TEXT", "textQuery": {"text": "What is the capital of France?"}}
        ],
        sources=[
            {
                "type": "INLINE",
                "inlineDocumentSource": {
                    "type": "TEXT",
                    "textDocument": {"text": irrelevant_text},
                },
            },
            {
                "type": "INLINE",
                "inlineDocumentSource": {
                    "type": "TEXT",
                    "textDocument": {"text": relevant_text},
                },
            },
        ],
        rerankingConfiguration={
            "type": "BEDROCK_RERANKING_MODEL",
            "bedrockRerankingConfiguration": {
                "numberOfResults": 2,
                "modelConfiguration": {"modelArn": model_arn},
            },
        },
    )

    results = resp["results"]
    assert len(results) == 2, f"expected 2 reranked results, got {len(results)}"

    scores = [r["relevanceScore"] for r in results]
    assert scores == sorted(scores, reverse=True), "results not sorted by relevanceScore"

    # the France source (index 1) was the relevant one and must outrank index 0
    top = results[0]
    assert top["index"] == 1, f"expected the relevant source to rank first, got index {top['index']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
