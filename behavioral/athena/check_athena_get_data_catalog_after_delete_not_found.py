"""athena-get-data-catalog-after-delete-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "athena-get-data-catalog-after-delete-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteDataCatalog, GetDataCatalog for that Name raises InvalidRequestException,
    the name is absent from ListDataCatalogs, and a further mutation on the dead name
    (UpdateDataCatalog) is rejected the same way."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-athena-cat-")

    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": "get-data-catalog-after-delete-not-found"}],
    )

    deleted = False

    def _cleanup():
        if not deleted:
            try:
                athena.delete_data_catalog(Name=name)
            except ClientError as exc:
                if "not found" not in exc.response["Error"].get("Message", ""):
                    raise

    ctx.on_cleanup(_cleanup)

    # Positive control: the catalog is readable while it exists.
    status = athena.get_data_catalog(Name=name)["DataCatalog"]["Status"]
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE before delete, got {status}"

    athena.delete_data_catalog(Name=name)
    deleted = True

    code, message = _error(lambda: athena.get_data_catalog(Name=name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException on GetDataCatalog after delete, got {code}"
    expected = f"DataCatalog {name} was not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    names = [c["CatalogName"] for c in athena.list_data_catalogs()["DataCatalogsSummary"]]
    assert name not in names, f"expected {name} absent from ListDataCatalogs after delete, still present in {names}"

    # A mutation on the now-dead name is rejected too, not just reads.
    update_code, update_message = _error(
        lambda: athena.update_data_catalog(Name=name, Type="GLUE", Parameters={"catalog-id": account_id}),
    )
    assert update_code == "InvalidRequestException", (
        f"expected InvalidRequestException updating deleted catalog {name}, got {update_code}"
    )
    expected_update = f"DataCatalog {name} does not exist."
    assert update_message == expected_update, f"expected message {expected_update!r}, got {update_message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
