"""list-data-catalogs-pagination-completeness."""
from __future__ import annotations

from collections import Counter

from behavioral_harness import tags

CHECK = "list-data-catalogs-pagination-completeness"
GROUP = "ordering"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDataCatalogs, paged via NextToken, returns every created catalog exactly once."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    base = ctx.unique_name("sim2real-cat-")
    names = [f"{base}-{i}" for i in range(5)]
    for name in names:
        athena.create_data_catalog(
            Name=name,
            Type="GLUE",
            Parameters={"catalog-id": account_id},
        )
        ctx.on_cleanup(lambda n=name: athena.delete_data_catalog(Name=n))

    seen: list[str] = []
    next_token = None
    while True:
        kwargs = {"MaxResults": 2}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = athena.list_data_catalogs(**kwargs)
        for summary in resp.get("DataCatalogsSummary", []):
            catalog_name = summary["CatalogName"]
            if catalog_name.startswith(base):
                seen.append(catalog_name)
        next_token = resp.get("NextToken")
        if not next_token:
            break

    counts = Counter(seen)
    assert set(counts.keys()) == set(names), (
        f"expected exactly {sorted(names)}, saw {sorted(counts.keys())}"
    )
    for name in names:
        assert counts[name] == 1, (
            f"expected catalog {name} exactly once across pages, appeared {counts[name]} times"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
