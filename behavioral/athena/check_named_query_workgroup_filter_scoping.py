"""named-query-workgroup-filter-scoping."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "named-query-workgroup-filter-scoping"
GROUP = "named-query"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNamedQueries(WorkGroup=X) returns only the named queries created under workgroup X;
    a named query created in workgroup A is not visible when listing workgroup B."""
    athena = ctx.client("athena")
    wg_a = ctx.unique_name("sim2real-athena-wga-")
    wg_b = ctx.unique_name("sim2real-athena-wgb-")
    athena.create_work_group(Name=wg_a, Tags=[{"Key": "sim2real", "Value": "named-query-workgroup-filter-scoping"}])
    athena.create_work_group(Name=wg_b, Tags=[{"Key": "sim2real", "Value": "named-query-workgroup-filter-scoping"}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_a, RecursiveDeleteOption=True))
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_b, RecursiveDeleteOption=True))

    nq_id = athena.create_named_query(
        Name=ctx.unique_name("sim2real-nq-"),
        Database="default",
        QueryString="SELECT 1",
        WorkGroup=wg_a,
    )["NamedQueryId"]

    ids_in_a = athena.list_named_queries(WorkGroup=wg_a)["NamedQueryIds"]
    ids_in_b = athena.list_named_queries(WorkGroup=wg_b)["NamedQueryIds"]

    assert nq_id in ids_in_a, (nq_id, ids_in_a)
    assert nq_id not in ids_in_b, (nq_id, ids_in_b)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
