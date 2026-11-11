"""list-named-queries-reflects-creation-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-named-queries-reflects-creation-order"
GROUP = "ordering"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNamedQueries, scoped to a dedicated workgroup, lists exactly the created named
    queries, each once, with a paginated listing that is stable across repeated calls."""
    athena = ctx.client("athena")

    wg_name = ctx.unique_name("sim2real-nq-wg-")
    athena.create_work_group(
        Name=wg_name, Tags=[{"Key": "sim2real", "Value": "list-named-queries-reflects-creation-order"}]
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    created_ids: list[str] = []
    for i in range(6):
        name = ctx.unique_name(f"sim2real-nq-{i}-")
        resp = athena.create_named_query(
            Name=name, Database="default", QueryString=f"SELECT {i}", WorkGroup=wg_name
        )
        nq_id = resp["NamedQueryId"]
        created_ids.append(nq_id)

    first_pass = _list_all_named_queries(athena, wg_name)
    second_pass = _list_all_named_queries(athena, wg_name)

    for nq_id in created_ids:
        count = first_pass.count(nq_id)
        assert count == 1, f"expected {nq_id} exactly once in ListNamedQueries, saw {count}"

    assert len(first_pass) == len(set(first_pass)), "ListNamedQueries returned a duplicate NamedQueryId across pages"
    assert first_pass == second_pass, "ListNamedQueries pagination order changed across repeated calls"
    # ListNamedQueries documents no listing order, so the dedicated workgroup's ids compare as a set.
    assert set(first_pass) == set(created_ids), (
        f"ListNamedQueries must list exactly the created named queries: created={created_ids} "
        f"listed={first_pass}"
    )


def _list_all_named_queries(athena, workgroup: str) -> list[str]:
    ids: list[str] = []
    token = None
    while True:
        kwargs = {"WorkGroup": workgroup, "MaxResults": 2}
        if token:
            kwargs["NextToken"] = token
        resp = athena.list_named_queries(**kwargs)
        ids.extend(resp.get("NamedQueryIds", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
