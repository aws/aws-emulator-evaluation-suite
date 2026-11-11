"""list-query-executions-pagination-no-gaps-or-dupes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-query-executions-pagination-no-gaps-or-dupes"
GROUP = "ordering"
SERVICES = ["athena"]

_N = 6


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paginating ListQueryExecutions (MaxResults=2) across all pages returns every
    QueryExecutionId created in a dedicated workgroup exactly once, with the same
    relative order recovered by two independent, back-to-back full pagination sweeps."""
    athena = ctx.client("athena")
    wg_name = ctx.unique_name("sim2real-athena-wg-")
    fake_bucket = ctx.unique_name("sim2real-athena-out-")
    athena.create_work_group(
        Name=wg_name,
        Configuration={"ResultConfiguration": {"OutputLocation": f"s3://{fake_bucket}/"}},
        Tags=[{"Key": "sim2real", "Value": "list-query-executions-pagination-no-gaps-or-dupes"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    created_ids = []
    for _ in range(_N):
        # The output bucket does not need to actually exist: StartQueryExecution hands
        # back a QueryExecutionId synchronously and the query fails later during
        # execution -- that failure is irrelevant to listing/pagination behavior.
        resp = athena.start_query_execution(QueryString="SELECT 1", WorkGroup=wg_name)
        created_ids.append(resp["QueryExecutionId"])

    sweep_a = _paginate_query_executions(athena, wg_name)
    sweep_b = _paginate_query_executions(athena, wg_name)

    assert len(sweep_a) == len(set(sweep_a)), "duplicate QueryExecutionIds within one pagination sweep"
    assert set(sweep_a) == set(created_ids), (
        f"pagination did not surface every created id exactly once: "
        f"missing={set(created_ids) - set(sweep_a)} unexpected={set(sweep_a) - set(created_ids)}"
    )
    assert sweep_a == sweep_b, (
        "relative order of QueryExecutionIds changed between two independent, "
        "back-to-back full pagination sweeps of the same workgroup"
    )


def _paginate_query_executions(athena, wg_name: str) -> list[str]:
    ids: list[str] = []
    token = None
    while True:
        kwargs = {"WorkGroup": wg_name, "MaxResults": 2}
        if token:
            kwargs["NextToken"] = token
        resp = athena.list_query_executions(**kwargs)
        ids.extend(resp.get("QueryExecutionIds", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
