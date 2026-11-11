"""data-catalog-lifecycle-create-get-update-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "data-catalog-lifecycle-create-get-update-delete"
GROUP = 'data-catalog'
SERVICES = ['athena']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DataCatalog supports create -> get -> update -> delete with Parameters preserved."""
    athena = ctx.client("athena")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-catalog-")
    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Description="v1",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": "data-catalog-lifecycle-create-get-update-delete"}],
    )
    ctx.on_cleanup(lambda: _delete_if_present(athena, name))

    got = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["Type"] == "GLUE", f"expected Type GLUE, got {got['Type']!r}"
    assert got["Description"] == "v1", f"expected Description v1, got {got['Description']!r}"
    assert got["Parameters"]["catalog-id"] == account_id, (
        f"expected Parameters['catalog-id'] {account_id!r}, got {got['Parameters'].get('catalog-id')!r}"
    )

    athena.update_data_catalog(
        Name=name, Type="GLUE", Description="v2", Parameters={"catalog-id": account_id}
    )
    updated = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert updated["Description"] == "v2", f"expected Description v2, got {updated['Description']!r}"

    athena.delete_data_catalog(Name=name)

    code, message = _error(lambda: athena.get_data_catalog(Name=name))
    assert code == "InvalidRequestException", f"expected data catalog gone, got {code}"
    assert message == f"DataCatalog {name} was not found.", message

    # A mutation on the dead name must also fail, not just a read. The
    # update carries valid GLUE parameters, so the only thing wrong with it is the dead name.
    update_code, update_message = _error(
        lambda: athena.update_data_catalog(
            Name=name, Type="GLUE", Description="v3", Parameters={"catalog-id": account_id}
        )
    )
    assert update_code == "InvalidRequestException", (
        f"expected UpdateDataCatalog on a deleted catalog to fail with InvalidRequestException, got {update_code}"
    )
    assert update_message == f"DataCatalog {name} does not exist.", update_message


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
    """Teardown that tolerates the check's own DeleteDataCatalog having already run."""
    from botocore.exceptions import ClientError

    try:
        athena.delete_data_catalog(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidRequestException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
