"""list-named-queries-pagination-completeness."""
from __future__ import annotations

from collections import Counter

from behavioral_harness import tags

CHECK = "list-named-queries-pagination-completeness"
GROUP = "ordering"
SERVICES = ["athena"]


def _list_all_named_query_ids(athena, workgroup: str) -> list[str]:
    ids: list[str] = []
    next_token = None
    while True:
        kwargs = {"WorkGroup": workgroup, "MaxResults": 2}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = athena.list_named_queries(**kwargs)
        ids.extend(resp.get("NamedQueryIds", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return ids


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNamedQueries, paged via NextToken, returns every created query exactly once in a stable order."""
    athena = ctx.client("athena")
    workgroup = ctx.unique_name("sim2real-wg-")
    athena.create_work_group(
        Name=workgroup, Tags=[{"Key": "sim2real", "Value": "behavioral-check"}]
    )
    ctx.on_cleanup(
        lambda: athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True)
    )

    base = ctx.unique_name("sim2real-nq-")
    expected_ids = []
    for i in range(6):
        resp = athena.create_named_query(
            Name=f"{base}-{i}",
            Database="default",
            QueryString="SELECT 1",
            WorkGroup=workgroup,
        )
        expected_ids.append(resp["NamedQueryId"])

    first_pass = _list_all_named_query_ids(athena, workgroup)
    second_pass = _list_all_named_query_ids(athena, workgroup)

    assert Counter(first_pass) == Counter(expected_ids), (
        f"expected ids {sorted(expected_ids)}, first pass saw {sorted(first_pass)}"
    )
    for qid, count in Counter(first_pass).items():
        assert count == 1, f"named query {qid} appeared {count} times in one pagination pass"

    assert first_pass == second_pass, (
        "ListNamedQueries pagination order changed across two consecutive full listings "
        f"with no mutations in between: {first_pass!r} != {second_pass!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
