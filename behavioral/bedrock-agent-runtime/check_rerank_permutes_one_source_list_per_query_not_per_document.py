"""rerank-permutes-one-source-list-per-query-not-per-document."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rerank-permutes-one-source-list-per-query-not-per-document"
GROUP = "model-invoke"
SERVICES = ["bedrock-agent-runtime"]

_RERANK_MODEL_ID = "amazon.rerank-v1:0"

# Four topically disjoint sources. Index positions are load-bearing, so they are named.
_SOURCE_TEXTS = [
    "Bananas are an excellent dietary source of potassium and magnesium.",  # 0
    "The Pacific Ocean is the largest and deepest of Earth's oceans.",  # 1
    "Paris is the capital city of France and sits on the river Seine.",  # 2
    "Mount Everest is the highest mountain above mean sea level.",  # 3
]
_BANANA_IDX = 0
_FRANCE_IDX = 2

_QUERY_FRANCE = "What is the capital city of France?"
_QUERY_POTASSIUM = "Which food is a good dietary source of potassium?"

# Fixed API constants from the Smithy model.
_NOR_MIN = 1  # BedrockRerankingConfiguration.numberOfResults range {min: 1}
_QUERIES_MAX = 1  # RerankQueriesList length {min: 1, max: 1}


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Rerank returns a query-dependent permutation of the source list: the same four sources rank
    differently under two different queries, and numberOfResults truncates that one ranking."""
    runtime = ctx.client("bedrock-agent-runtime")
    # The rejection arms push numberOfResults/queries outside the modelled range on purpose; botocore
    # enforces the same min/max client-side, so this client disables that local check and the
    # malformed request reaches the service, whose ValidationException is what gets asserted.
    unvalidated = ctx.client("bedrock-agent-runtime", config=Config(parameter_validation=False))
    model_arn = f"arn:aws:bedrock:{ctx.region}::foundation-model/{_RERANK_MODEL_ID}"
    n_sources = len(_SOURCE_TEXTS)

    # ---- Independent resource this check also exercises at its terminal read.
    control_session = runtime.create_session()["sessionId"]
    ctx.on_cleanup(lambda: _teardown_session(runtime, control_session))
    control_status = runtime.get_session(sessionIdentifier=control_session)["sessionStatus"]
    assert control_status == "ACTIVE", (
        f"a freshly created bedrock-agent-runtime session must read back ACTIVE; got "
        f"{control_status!r}"
    )

    def _rerank(
        query: str, number_of_results: int, *, queries: list | None = None, client=None
    ) -> list[dict]:
        return (client or runtime).rerank(
            queries=queries
            if queries is not None
            else [{"type": "TEXT", "textQuery": {"text": query}}],
            sources=[
                {
                    "type": "INLINE",
                    "inlineDocumentSource": {"type": "TEXT", "textDocument": {"text": text}},
                }
                for text in _SOURCE_TEXTS
            ],
            rerankingConfiguration={
                "type": "BEDROCK_RERANKING_MODEL",
                "bedrockRerankingConfiguration": {
                    "numberOfResults": number_of_results,
                    "modelConfiguration": {"modelArn": model_arn},
                },
            },
        )["results"]

    # ---- Arm A: the France query over all four sources; the call is asserted to succeed outright.
    france = _rerank(_QUERY_FRANCE, n_sources)
    _assert_permutation(france, n_sources, label=f"query={_QUERY_FRANCE!r}")
    france_indices = [r["index"] for r in france]
    assert france_indices[0] == _FRANCE_IDX, (
        f"the France query must rank source {_FRANCE_IDX} "
        f"({_SOURCE_TEXTS[_FRANCE_IDX][:40]!r}...) first; got index {france_indices[0]} "
        f"({_SOURCE_TEXTS[france_indices[0]][:40]!r}...), full ranking {france_indices} with "
        f"scores {[r['relevanceScore'] for r in france]}"
    )

    # ---- Arm B: the TWIN CONTROL. Identical source list, identical configuration, different
    # query, run seconds later. Returning input order, a fixed permutation, or a query-blind
    # document score fails here.
    potassium = _rerank(_QUERY_POTASSIUM, n_sources)
    _assert_permutation(potassium, n_sources, label=f"query={_QUERY_POTASSIUM!r}")
    potassium_indices = [r["index"] for r in potassium]
    assert potassium_indices[0] == _BANANA_IDX, (
        f"the potassium query over the SAME four sources must rank source {_BANANA_IDX} "
        f"({_SOURCE_TEXTS[_BANANA_IDX][:40]!r}...) first; got index {potassium_indices[0]} "
        f"({_SOURCE_TEXTS[potassium_indices[0]][:40]!r}...), full ranking {potassium_indices}"
    )
    assert potassium_indices[0] != france_indices[0], (
        f"the ranking must depend on the QUERY: both queries put index {france_indices[0]} first "
        f"over the identical source list, so the reranker is scoring documents without reading "
        f"the query. France ranking {france_indices}, potassium ranking {potassium_indices}"
    )
    assert potassium_indices != france_indices, (
        f"two disjoint queries returned the identical permutation {france_indices} of the same "
        f"four sources"
    )

    # ---- Truncation, not reselection.
    top1 = _rerank(_QUERY_FRANCE, _NOR_MIN)
    assert len(top1) == 1, (
        f"numberOfResults={_NOR_MIN} must return exactly 1 result; got {len(top1)}"
    )
    assert top1[0]["index"] == france_indices[0], (
        f"numberOfResults must TRUNCATE the ranking, not select a different set: "
        f"numberOfResults=1 returned index {top1[0]['index']} while the head of the full ranking "
        f"was {france_indices[0]}"
    )
    assert top1[0]["relevanceScore"] == france[0]["relevanceScore"], (
        f"the same source must carry the same relevanceScore across calls differing only in "
        f"numberOfResults: {top1[0]['relevanceScore']} vs {france[0]['relevanceScore']}"
    )

    # ---- Rejections. Neither input can ever become valid, so neither has a restore beat. Arms A
    # and B above are the positive control that separates these from "rejects every Rerank".
    below, below_message = _error_code(
        lambda: _rerank(_QUERY_FRANCE, _NOR_MIN - 1, client=unvalidated)
    )
    assert below == "ValidationException", (
        f"numberOfResults={_NOR_MIN - 1} is below the modelled minimum {_NOR_MIN} and must be "
        f"rejected with ValidationException; got {below!r}"
    )
    assert below_message == "1 validation error detected: Value '0' at 'rerankingConfiguration.bedrockRerankingConfiguration.numberOfResults' failed to satisfy constraint: Member must have value greater than or equal to 1", (
        f"expected the exact ValidationException message AWS returns, got {below_message!r}"
    )
    # Built to exactly one past the modelled maximum, so the length is structural rather than
    # asserted over constants.
    two_queries = [
        {"type": "TEXT", "textQuery": {"text": q}}
        for q in (_QUERY_FRANCE, _QUERY_POTASSIUM)[: _QUERIES_MAX + 1]
    ]
    many, many_message = _error_code(
        lambda: _rerank(_QUERY_FRANCE, n_sources, queries=two_queries, client=unvalidated)
    )
    assert many == "ValidationException", (
        f"{_QUERIES_MAX + 1} entries exceeds the modelled RerankQueriesList maximum of "
        f"{_QUERIES_MAX} and must be rejected with ValidationException; got {many!r}"
    )
    assert many_message == "1 validation error detected: Value at 'queries' failed to satisfy constraint: Member must have length less than or equal to 1", (
        f"expected the exact ValidationException message AWS returns, got {many_message!r}"
    )

    # ---- Freeze detector: with the rejections behind us, the identical accepted call must
    # still return the identical ranking AND the identical scores. This is what makes arm B's
    # "the ranking changed" a signal rather than noise, and it needs no timing assumption at all.
    for attempt in range(3):
        repeat = _rerank(_QUERY_FRANCE, n_sources)
        assert [r["index"] for r in repeat] == france_indices, (
            f"repeat #{attempt + 1} of the identical Rerank returned a different permutation: "
            f"{[r['index'] for r in repeat]} != {france_indices}"
        )
        assert [r["relevanceScore"] for r in repeat] == [r["relevanceScore"] for r in france], (
            f"repeat #{attempt + 1} of the identical Rerank returned different scores: "
            f"{[r['relevanceScore'] for r in repeat]} != "
            f"{[r['relevanceScore'] for r in france]}"
        )

    # ---- Terminal read: Rerank is a pure function with no reader, so the terminal assertion is a
    # CONSEQUENCE at an independent resource -- the session this check created is still usable and
    # honours its own delete-and-verify contract after 7 model calls.
    runtime.end_session(sessionIdentifier=control_session)
    ended = runtime.get_session(sessionIdentifier=control_session)["sessionStatus"]
    assert ended == "ENDED", f"the control session must read back ENDED after end_session; got {ended!r}"
    runtime.delete_session(sessionIdentifier=control_session)
    gone, gone_message = _error_code(lambda: runtime.get_session(sessionIdentifier=control_session))
    assert gone == "ResourceNotFoundException", (
        f"after delete_session, GetSession on the dead id must fail with "
        f"ResourceNotFoundException; got {gone!r}"
    )
    assert gone_message == f"Session with ID {control_session} not found", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {gone_message!r}"
    )


# ===== helpers =====


def _assert_permutation(results: list[dict], n_sources: int, *, label: str) -> None:
    """The result list is a scored permutation of the requested slice of the sources."""
    assert len(results) == n_sources, (
        f"{label}: numberOfResults={n_sources} over {n_sources} sources must return "
        f"{n_sources} results; got {len(results)}"
    )
    indices = [r["index"] for r in results]
    out_of_range = [i for i in indices if not 0 <= i < n_sources]
    assert out_of_range == [], (
        f"{label}: result index/indices {out_of_range} are not valid positions in a "
        f"{n_sources}-source list; full ranking {indices}"
    )
    assert len(set(indices)) == len(indices), (
        f"{label}: Rerank must permute the sources, so no source may appear twice; got "
        f"{indices}"
    )
    assert set(indices) == set(range(n_sources)), (
        f"{label}: with numberOfResults equal to the source count the result set must cover every "
        f"source exactly once; got {sorted(indices)}, expected {list(range(n_sources))}"
    )
    scores = [r["relevanceScore"] for r in results]
    assert scores == sorted(scores, reverse=True), (
        f"{label}: results must be ordered by non-increasing relevanceScore; got {scores} for "
        f"ranking {indices}"
    )


def _error_code(fn) -> tuple[str, str]:
    """Return the ClientError code and message, or RAISE on unexpected success."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _teardown_session(runtime, session_id: str) -> None:
    """End the session if still ACTIVE (DeleteSession refuses an ACTIVE one), then delete it."""
    try:
        status = runtime.get_session(sessionIdentifier=session_id)["sessionStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "ACTIVE":
        try:
            runtime.end_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    try:
        runtime.delete_session(sessionIdentifier=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
