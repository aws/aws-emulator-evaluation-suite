"""batch-get-named-query-partial-unprocessed."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-named-query-partial-unprocessed"
GROUP = 'named-query'
SERVICES = ['athena']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetNamedQuery returns valid ids in NamedQueries and bogus ones as unprocessed."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-nq-")
    nq_id = athena.create_named_query(
        Name=name, Database="default", QueryString="SELECT 1"
    )["NamedQueryId"]
    ctx.on_cleanup(lambda: athena.delete_named_query(NamedQueryId=nq_id))

    bogus_id = "00000000-0000-0000-0000-000000000000"
    resp = athena.batch_get_named_query(NamedQueryIds=[nq_id, bogus_id])

    found_ids = {nq["NamedQueryId"] for nq in resp["NamedQueries"]}
    unprocessed = {u["NamedQueryId"]: u for u in resp["UnprocessedNamedQueryIds"]}
    assert nq_id in found_ids, "valid named query id missing from NamedQueries"
    assert bogus_id in unprocessed, "bogus id should be reported as unprocessed, not silently dropped"
    assert bogus_id not in found_ids, f"bogus id should not resolve, but found it in NamedQueries: {found_ids}"
    assert unprocessed[bogus_id].get("ErrorCode"), f"unprocessed entry missing ErrorCode: {unprocessed[bogus_id]}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
