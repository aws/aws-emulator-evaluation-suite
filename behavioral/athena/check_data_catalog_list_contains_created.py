"""data-catalog-list-contains-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "data-catalog-list-contains-created"
GROUP = 'data-catalog'
SERVICES = ['athena']

def _list_all_catalogs(athena):
    items = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = athena.list_data_catalogs(**kwargs)
        items.extend(resp.get("DataCatalogsSummary", []))
        token = resp.get("NextToken")
        if not token:
            return items

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDataCatalogs surfaces a newly created catalog with its type."""
    athena = ctx.client("athena")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-catalog-")
    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": "data-catalog-list-contains-created"}],
    )
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=name))

    found = None
    for c in _list_all_catalogs(athena):
        if c["CatalogName"] == name:
            found = c
            break

    assert found is not None, "created data catalog not found in ListDataCatalogs"
    assert found["Type"] == "GLUE", f"expected Type GLUE, got {found['Type']}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
