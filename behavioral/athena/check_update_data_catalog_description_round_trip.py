"""update-data-catalog-description-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-data-catalog-description-round-trip"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDataCatalog persists a new Description for an existing catalog and rejects an unknown Name."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real_athena_cat_")
    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Description="initial description",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_if_present(athena, name))

    created = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert created["Description"] == "initial description", created["Description"]
    assert created["Type"] == "GLUE", created["Type"]

    # success path: update the description, Type must be repeated (immutable) but value changes.
    athena.update_data_catalog(
        Name=name,
        Type="GLUE",
        Description="updated description",
        Parameters={"catalog-id": account_id},
    )
    updated = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert updated["Description"] == "updated description", updated["Description"]
    assert updated["Type"] == "GLUE", updated["Type"]
    assert updated["Name"] == name, updated["Name"]

    # error boundary: updating a data catalog Name that does not exist is rejected.
    missing_name = ctx.unique_name("sim2real_athena_missing_cat_")
    code, message = _error(lambda: athena.update_data_catalog(
        Name=missing_name,
        Type="GLUE",
        Description="won't apply",
        Parameters={"catalog-id": account_id},
    ))
    assert code == "InvalidRequestException", code
    assert message == f"DataCatalog {missing_name} does not exist.", message

    # positive control: the missing name truly was never created.
    list_names = {c["CatalogName"] for c in athena.list_data_catalogs()["DataCatalogsSummary"]}
    assert missing_name not in list_names, list_names

    # Cleanup already deletes this catalog; prove that delete is real and unassailable
    # before on_cleanup's delete runs (it tolerates the catalog being gone).
    athena.delete_data_catalog(Name=name)
    gone_code, gone_message = _error(lambda: athena.get_data_catalog(Name=name))
    assert gone_code == "InvalidRequestException", gone_code
    assert gone_message == f"DataCatalog {name} was not found.", gone_message
    dead_update_code, dead_update_message = _error(lambda: athena.update_data_catalog(
        Name=name,
        Type="GLUE",
        Description="should not apply",
        Parameters={"catalog-id": account_id},
    ))
    assert dead_update_code == "InvalidRequestException", dead_update_code
    assert dead_update_message == f"DataCatalog {name} does not exist.", dead_update_message


def _delete_if_present(athena, name):
    from botocore.exceptions import ClientError
    try:
        athena.delete_data_catalog(Name=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "InvalidRequestException":
            raise


def _error(fn):
    """Call fn(); return the botocore Error.Code and Message if it raises. An unexpected SUCCESS
    raises, because an emulator accepting input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
