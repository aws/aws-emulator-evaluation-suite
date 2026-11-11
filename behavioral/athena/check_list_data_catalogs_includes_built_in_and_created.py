"""list-data-catalogs-includes-built-in-and-created."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-data-catalogs-includes-built-in-and-created"
GROUP = "ordering"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDataCatalogs always includes the built-in AwsDataCatalog alongside any
    user-created catalogs, with a stable, deduplicated listing across pagination."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    created_names: list[str] = []
    for i in range(3):
        name = ctx.unique_name(f"sim2real-cat-{i}-")
        athena.create_data_catalog(
            Name=name,
            Type="GLUE",
            Parameters={"catalog-id": account_id},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        created_names.append(name)
        ctx.on_cleanup(lambda name=name: athena.delete_data_catalog(Name=name))

    # ListDataCatalogs is account-wide: only the built-in and this check's own catalogs are graded,
    # and a pair of sweeps that another caller's creates or deletes shifted is taken again (bounded).
    graded = {"AwsDataCatalog", *created_names}
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        first_pass = [n for n in _list_all_catalogs(athena) if n in graded]
        second_pass = [n for n in _list_all_catalogs(athena) if n in graded]
        if all(first_pass.count(n) == 1 and second_pass.count(n) == 1 for n in graded):
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("ListDataCatalogs listing each graded catalog once: the run "
                                   "budget ended first; not graded")
            break
        time.sleep(2)

    assert "AwsDataCatalog" in first_pass, "built-in AwsDataCatalog missing from ListDataCatalogs"
    for name in created_names:
        count = first_pass.count(name)
        assert count == 1, f"expected catalog {name} exactly once, saw {count}"

    assert len(first_pass) == len(set(first_pass)), "ListDataCatalogs returned a duplicate CatalogName across pages"
    assert first_pass == second_pass, "ListDataCatalogs pagination order changed across repeated calls"


def _list_all_catalogs(athena) -> list[str]:
    names: list[str] = []
    token = None
    while True:
        kwargs = {"MaxResults": 2}
        if token:
            kwargs["NextToken"] = token
        resp = athena.list_data_catalogs(**kwargs)
        names.extend(c["CatalogName"] for c in resp.get("DataCatalogsSummary", []))
        token = resp.get("NextToken")
        if not token:
            break
    return names


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
