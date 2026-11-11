"""op-contract-updateDataCatalog."""
from __future__ import annotations

CHECK = "op-contract-updateDataCatalog"
GROUP = "error-semantics"
SERVICES = ["athena"]

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp is not None:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDataCatalog mutates Description in place; updating a nonexistent catalog is rejected."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    catalog_name = ctx.unique_name("sim2real_behav_catalog_")

    athena.create_data_catalog(
        Name=catalog_name,
        Type="GLUE",
        Description="initial description",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": "op-contract-update-data-catalog"}],
    )
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=catalog_name))

    before = athena.get_data_catalog(Name=catalog_name)["DataCatalog"]
    assert before["Name"] == catalog_name, before
    assert before["Type"] == "GLUE", before
    assert before["Description"] == "initial description", before

    athena.update_data_catalog(
        Name=catalog_name,
        Type="GLUE",
        Description="updated description",
        Parameters={"catalog-id": account_id},
    )
    after = athena.get_data_catalog(Name=catalog_name)["DataCatalog"]
    assert after["Description"] == "updated description", after
    # Type and Name are immutable identity fields, unaffected by the update.
    assert after["Name"] == catalog_name, after
    assert after["Type"] == "GLUE", after

    # Error boundary: updating a data catalog Name that does not exist.
    missing_name = ctx.unique_name("sim2real_behav_missing_catalog_")
    code, message = _error(
        lambda: athena.update_data_catalog(
            Name=missing_name,
            Type="GLUE",
            Description="x",
            Parameters={"catalog-id": account_id},
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == f"DataCatalog {missing_name} does not exist.", message

    # Confirm the failed update did not create a catalog under that name.
    code2, message2 = _error(lambda: athena.get_data_catalog(Name=missing_name))
    assert code2 == "InvalidRequestException", f"expected catalog {missing_name} to not exist, got {code2}"
    assert message2 == f"DataCatalog {missing_name} was not found.", message2


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
