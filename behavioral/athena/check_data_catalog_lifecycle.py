"""data-catalog-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "data-catalog-lifecycle"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataCatalog of type GLUE completes synchronously (CREATE_COMPLETE);
    GetDataCatalog/ListDataCatalogs/UpdateDataCatalog/DeleteDataCatalog round-trip it."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-athena-cat-")

    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Description="behavioral check catalog",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": "data-catalog-lifecycle"}],
    )

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            athena.delete_data_catalog(Name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidRequestException":
                raise

    ctx.on_cleanup(_cleanup)

    got = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert got["Type"] == "GLUE", got["Type"]
    assert got["Status"] == "CREATE_COMPLETE", got["Status"]
    assert got["Description"] == "behavioral check catalog", got["Description"]

    names = [c["CatalogName"] for c in athena.list_data_catalogs()["DataCatalogsSummary"]]
    assert name in names, (name, names)

    athena.update_data_catalog(
        Name=name,
        Type="GLUE",
        Description="updated desc",
        Parameters={"catalog-id": account_id},
    )
    got2 = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert got2["Description"] == "updated desc", got2["Description"]

    athena.delete_data_catalog(Name=name)
    code, message = _error(lambda: athena.get_data_catalog(Name=name))
    assert code == "InvalidRequestException", code
    assert message == f"DataCatalog {name} was not found.", message

    # The delete is not just a stale read — a mutation against the dead id must
    # also fail, with the same not-found code as the read.
    update_code, update_message = _error(
        lambda: athena.update_data_catalog(
            Name=name,
            Type="GLUE",
            Description="post-delete update",
            Parameters={"catalog-id": account_id},
        )
    )
    assert update_code == "InvalidRequestException", update_code
    assert update_message == f"DataCatalog {name} does not exist.", update_message

    names_after = [c["CatalogName"] for c in athena.list_data_catalogs()["DataCatalogsSummary"]]
    assert name not in names_after, (name, names_after)


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts what real AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
