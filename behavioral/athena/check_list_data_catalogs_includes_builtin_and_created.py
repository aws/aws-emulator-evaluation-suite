"""list-data-catalogs-includes-builtin-and-created."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-data-catalogs-includes-builtin-and-created"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDataCatalogs always includes the built-in AwsDataCatalog plus any
    user-created catalogs, and removes a catalog immediately after
    DeleteDataCatalog."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-catalog-")

    before = _catalog_summaries(athena)
    before_names = {c["CatalogName"] for c in before}
    assert "AwsDataCatalog" in before_names, f"expected built-in AwsDataCatalog in {before_names}"
    assert name not in before_names, f"unique catalog name {name} already present before creation"

    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_catalog(athena, name))

    after_create = _catalog_summaries(athena)
    match = next((c for c in after_create if c["CatalogName"] == name), None)
    assert match is not None, "created catalog missing from ListDataCatalogs immediately after creation"
    assert match["Type"] == "GLUE", f"expected Type GLUE, got {match['Type']}"
    assert match.get("Status") == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {match.get('Status')}"

    athena.delete_data_catalog(Name=name)
    after_delete_names = {c["CatalogName"] for c in _catalog_summaries(athena)}
    assert name not in after_delete_names, "deleted catalog still present in ListDataCatalogs"


def _catalog_summaries(athena):
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = athena.list_data_catalogs(**kwargs)
        out.extend(resp["DataCatalogsSummary"])
        token = resp.get("NextToken")
        if not token:
            break
    return out


def _safe_delete_catalog(athena, name):
    try:
        athena.delete_data_catalog(Name=name)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err.get("Code") == "InvalidRequestException" and "was not found" in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
