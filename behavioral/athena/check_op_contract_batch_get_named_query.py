"""op-contract-batchGetNamedQuery."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "op-contract-batchGetNamedQuery"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetNamedQuery returns full records for existing ids and routes unknown
    ids into UnprocessedNamedQueryIds instead of raising."""
    athena = ctx.client("athena")

    ids = []
    specs = {}
    for i in range(2):
        name = ctx.unique_name(f"sim2real-athena-nq{i}-")
        query = f"SELECT {i} AS col"
        qid = athena.create_named_query(
            Name=name, Database="default", QueryString=query, WorkGroup="primary"
        )["NamedQueryId"]
        ctx.on_cleanup(lambda q=qid: athena.delete_named_query(NamedQueryId=q))
        ids.append(qid)
        specs[qid] = (name, query)

    # Success path: both ids resolve, nothing unprocessed.
    resp = athena.batch_get_named_query(NamedQueryIds=ids)
    assert resp["UnprocessedNamedQueryIds"] == [], (
        f"expected no unprocessed ids for two real named queries, got {resp['UnprocessedNamedQueryIds']}"
    )
    got = {nq["NamedQueryId"]: nq for nq in resp["NamedQueries"]}
    assert set(got.keys()) == set(ids), f"expected {set(ids)}, got {set(got.keys())}"
    for qid, (name, query) in specs.items():
        assert got[qid]["Name"] == name, f"expected Name {name!r}, got {got[qid]['Name']!r}"
        assert got[qid]["QueryString"] == query, (
            f"expected QueryString {query!r}, got {got[qid]['QueryString']!r}"
        )
        assert got[qid]["Database"] == "default", (
            f"expected Database 'default', got {got[qid]['Database']!r}"
        )

    # Error boundary: an unknown id is routed to UnprocessedNamedQueryIds, not raised, with its own
    # per-item error code -- NAMED_QUERY_NOT_FOUND, distinct from the InvalidRequestException
    # GetNamedQuery raises for the equivalent single-id lookup. Confirmed against real AWS:
    # BatchGetNamedQuery does not reuse the singular operation's exception name for its
    # partial-failure entries.
    bogus = str(uuid.uuid4())
    resp2 = athena.batch_get_named_query(NamedQueryIds=[ids[0], bogus])
    assert [nq["NamedQueryId"] for nq in resp2["NamedQueries"]] == [ids[0]], (
        f"expected only {ids[0]!r} resolved, got {[nq['NamedQueryId'] for nq in resp2['NamedQueries']]}"
    )
    unprocessed = {u["NamedQueryId"]: u for u in resp2["UnprocessedNamedQueryIds"]}
    assert set(unprocessed.keys()) == {bogus}, f"expected {{{bogus!r}}}, got {set(unprocessed.keys())}"
    assert unprocessed[bogus].get("ErrorCode") == "NAMED_QUERY_NOT_FOUND", (
        f"expected ErrorCode 'NAMED_QUERY_NOT_FOUND', got {unprocessed[bogus].get('ErrorCode')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
