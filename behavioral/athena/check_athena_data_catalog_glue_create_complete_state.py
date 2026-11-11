"""athena-data-catalog-glue-create-complete-state."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "athena-data-catalog-glue-create-complete-state"
GROUP = "state"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A GLUE-type data catalog is created SYNCHRONOUSLY: Status is CREATE_COMPLETE immediately."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-athena-cat-")

    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Description="behavioral check glue catalog",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": "data-catalog-glue-create-complete-state"}],
    )

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            athena.delete_data_catalog(Name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidRequestException":
                raise

    ctx.on_cleanup(_cleanup)

    catalog = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert catalog["Name"] == name, f"expected Name={name!r}, got {catalog['Name']!r}"
    assert catalog["Type"] == "GLUE", f"expected Type=GLUE, got {catalog['Type']!r}"
    assert catalog["Status"] == "CREATE_COMPLETE", (
        f"expected Status=CREATE_COMPLETE immediately after create, got {catalog['Status']!r}"
    )
    assert catalog["Parameters"]["catalog-id"] == account_id, (
        f"expected Parameters['catalog-id']={account_id!r}, got {catalog['Parameters'].get('catalog-id')!r}"
    )

    names = [c["CatalogName"] for c in athena.list_data_catalogs()["DataCatalogsSummary"]]
    assert name in names, f"expected {name!r} in ListDataCatalogs, got {names!r}"

    athena.delete_data_catalog(Name=name)
    code, message = _error(lambda: athena.get_data_catalog(Name=name))
    assert code == "InvalidRequestException", (
        f"expected GetDataCatalog on deleted {name!r} to fail InvalidRequestException, got {code!r}"
    )
    assert message == f"DataCatalog {name} was not found.", message


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
