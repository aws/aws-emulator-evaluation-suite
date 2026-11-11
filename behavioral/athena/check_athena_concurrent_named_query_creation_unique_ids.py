"""athena-concurrent-named-query-creation-unique-ids."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "athena-concurrent-named-query-creation-unique-ids"
GROUP = "concurrency"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateNamedQuery calls (distinct names) each get a distinct NamedQueryId; none collide."""
    athena = ctx.client("athena")
    n = 10
    base = ctx.unique_name("sim2real-athena-nq-")
    names = [f"{base}-{i}" for i in range(n)]

    def _create(name: str) -> str:
        return athena.create_named_query(
            Name=name, Database="default", QueryString="SELECT 1"
        )["NamedQueryId"]

    ids: list[str] = []
    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_create, name) for name in names]
        for fut in as_completed(futures):
            ids.append(fut.result())

    for nq_id in ids:
        ctx.on_cleanup(lambda i=nq_id: athena.delete_named_query(NamedQueryId=i))

    assert len(ids) == n
    assert len(set(ids)) == n, f"expected {n} distinct NamedQueryIds under contention, got {set(ids)}"

    fetched = athena.batch_get_named_query(NamedQueryIds=ids)["NamedQueries"]
    assert len(fetched) == n
    fetched_names = {q["Name"] for q in fetched}
    assert fetched_names == set(names)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
