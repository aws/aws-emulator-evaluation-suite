"""data-catalog-glue-create-synchronous-and-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "data-catalog-glue-create-synchronous-and-delete"
GROUP = "data-catalog"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataCatalog for Type=GLUE completes synchronously: GetDataCatalog immediately
    after creation already reports Status CREATE_COMPLETE (no CREATE_IN_PROGRESS polling
    needed, unlike FEDERATED catalogs). DeleteDataCatalog then removes it for good."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-athena-cat-")

    # CreateDataCatalog's response body carries no "DataCatalog" element (it is empty on
    # success); the synchronous-completion claim is verified via a subsequent GetDataCatalog.
    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_if_present(athena, name))

    fetched = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert fetched["Name"] == name, f"expected Name={name!r}, got {fetched!r}"
    assert fetched["Type"] == "GLUE", f"expected Type=GLUE, got {fetched!r}"
    assert fetched["Status"] == "CREATE_COMPLETE", fetched

    athena.delete_data_catalog(Name=name)
    code, message = _error(lambda: athena.get_data_catalog(Name=name))
    assert code == "InvalidRequestException", code
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


def _delete_if_present(athena, name):
    from botocore.exceptions import ClientError

    try:
        athena.delete_data_catalog(Name=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "InvalidRequestException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
