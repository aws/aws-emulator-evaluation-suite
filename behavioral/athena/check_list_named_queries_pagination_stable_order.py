"""list-named-queries-pagination-stable-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-named-queries-pagination-stable-order"
GROUP = "ordering"
SERVICES = ["athena"]

_N = 6


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListNamedQueries (MaxResults=2) via NextToken across all pages returns
    every NamedQueryId created in a dedicated workgroup exactly once, with a stable,
    non-overlapping ordering recovered identically by two independent full sweeps."""
    athena = ctx.client("athena")
    wg_name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=wg_name, Tags=[{"Key": "sim2real", "Value": "behavioral-check"}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    created_ids = []
    for i in range(_N):
        resp = athena.create_named_query(
            Name=ctx.unique_name(f"sim2real-nq-{i}-"),
            Database="default",
            QueryString="SELECT 1",
            WorkGroup=wg_name,
        )
        created_ids.append(resp["NamedQueryId"])

    sweep_a = _paginate_named_queries(athena, wg_name)
    sweep_b = _paginate_named_queries(athena, wg_name)

    assert len(sweep_a) == len(set(sweep_a)), "duplicate NamedQueryIds within one pagination sweep"
    assert set(sweep_a) == set(created_ids), (
        f"pagination did not surface every created named query exactly once: "
        f"missing={set(created_ids) - set(sweep_a)} unexpected={set(sweep_a) - set(created_ids)}"
    )
    assert sweep_a == sweep_b, (
        "relative order of NamedQueryIds changed between two independent, "
        "back-to-back full pagination sweeps of the same workgroup"
    )


def _paginate_named_queries(athena, wg_name: str) -> list[str]:
    ids: list[str] = []
    token = None
    while True:
        kwargs = {"WorkGroup": wg_name, "MaxResults": 2}
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
