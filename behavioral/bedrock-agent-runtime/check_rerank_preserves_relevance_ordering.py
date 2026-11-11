"""rerank-preserves-relevance-ordering."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "rerank-preserves-relevance-ordering"
GROUP = "ordering"
SERVICES = ["bedrock-agent-runtime"]

_RERANK_MODEL_ARN_TEMPLATE = "arn:aws:bedrock:{region}::foundation-model/cohere.rerank-v3-5:0"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Rerank of six inline documents returns one result per document, each index once, sorted by
    descending relevanceScore."""
    client = ctx.client("bedrock-agent-runtime")

    documents = [
        "Amazon Bedrock is a fully managed service that offers a choice of foundation models.",
        "Amazon S3 is an object storage service offering industry-leading scalability.",
        "A recipe for sourdough bread requires flour, water, salt, and a starter culture.",
        "Amazon Bedrock lets you customize foundation models with your own data using fine-tuning.",
        "The Eiffel Tower is a wrought-iron lattice tower in Paris, France.",
        "Amazon Bedrock provides a serverless experience for building generative AI applications.",
    ]
    sources = [
        {"type": "INLINE", "inlineDocumentSource": {"type": "TEXT", "textDocument": {"text": doc}}}
        for doc in documents
    ]

    resp = client.rerank(
        queries=[{"type": "TEXT", "textQuery": {"text": "What is Amazon Bedrock?"}}],
        sources=sources,
        rerankingConfiguration={
            "type": "BEDROCK_RERANKING_MODEL",
            "bedrockRerankingConfiguration": {
                "modelConfiguration": {
                    "modelArn": _RERANK_MODEL_ARN_TEMPLATE.format(region=ctx.region)
                },
                "numberOfResults": len(documents),
            },
        },
    )

    results = resp["results"]
    assert len(results) == len(documents), (
        f"expected {len(documents)} reranked results, got {len(results)}"
    )

    scores = [r["relevanceScore"] for r in results]
    for i in range(1, len(scores)):
        assert scores[i - 1] >= scores[i], (
            f"Rerank results are not sorted by descending relevanceScore at index {i}: {scores}"
        )

    indices = [r["index"] for r in results]
    assert sorted(indices) == list(range(len(documents))), (
        f"Rerank result indices must be a permutation of the input sources, got {indices}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
