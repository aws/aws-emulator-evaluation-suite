"""list-named-queries-contains-created-and-stable-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-named-queries-contains-created-and-stable-order"
GROUP = "ordering"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNamedQueries returns newly created named queries for the workgroup, and two consecutive
    calls (no mutations in between) return the exact same order across pages."""
    athena = ctx.client("athena")
    glue = ctx.client("glue")
    wg_name = ctx.unique_name("sim2real-behav-nq-wg-")
    athena.create_work_group(
        Name=wg_name,
        Tags=[{"Key": "sim2real", "Value": "list-named-queries-contains-created-and-stable-order"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    db_name = ctx.unique_name("sim2real_behav_nq_db_").replace("-", "_")
    glue.create_database(
        DatabaseInput={"Name": db_name},
        Tags={"sim2real": "list-named-queries-contains-created-and-stable-order"},
    )
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    created_ids = []
    for i in range(4):
        resp = athena.create_named_query(
            Name=ctx.unique_name(f"sim2real-behav-nq-{i}-"),
            Database=db_name,
            QueryString=f"SELECT {i}",
            WorkGroup=wg_name,
        )
        created_ids.append(resp["NamedQueryId"])

    first_pass = _list_all_named_query_ids(athena, wg_name)
    second_pass = _list_all_named_query_ids(athena, wg_name)

    assert set(first_pass) == set(created_ids), (
        f"ListNamedQueries did not return exactly the created named queries: "
        f"missing={set(created_ids) - set(first_pass)} unexpected={set(first_pass) - set(created_ids)}"
    )

    assert first_pass == second_pass, (
        "ListNamedQueries returned a different order across two consecutive calls: "
        f"{first_pass} vs {second_pass}"
    )
    assert len(first_pass) == len(set(first_pass)), "ListNamedQueries returned duplicate ids"


def _list_all_named_query_ids(athena, workgroup: str) -> list[str]:
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
