"""data-catalog-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "data-catalog-duplicate-name-rejected"
GROUP = "representation"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second CreateDataCatalog with a Name in use fails InvalidRequestException and leaves the
    original's Type and Parameters unchanged, while a differently-named catalog is created."""
    athena = ctx.client("athena")
    catalog_name = ctx.unique_name("sim2real_behav_catdup_")
    original_params = {"catalog-id": "123456789012"}
    catalog_tags = [{"Key": "sim2real-check", "Value": "data-catalog-duplicate-name-rejected"}]

    athena.create_data_catalog(Name=catalog_name, Type="GLUE", Parameters=original_params, Tags=catalog_tags)
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=catalog_name))

    code, message = _error(
        lambda: athena.create_data_catalog(
            Name=catalog_name, Type="GLUE", Parameters={"catalog-id": "999999999999"}
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    assert message == f"DataCatalog {catalog_name} has already been created.", message

    # effect absent: the original catalog's parameters were not overwritten by the
    # rejected duplicate-create attempt.
    unchanged = athena.get_data_catalog(Name=catalog_name)["DataCatalog"]
    assert unchanged["Parameters"] == original_params
    assert unchanged["Type"] == "GLUE"

    # positive control: a distinct, differently-named catalog still creates fine.
    other_name = ctx.unique_name("sim2real_behav_catdup_other_")
    athena.create_data_catalog(
        Name=other_name, Type="GLUE", Parameters={"catalog-id": "111111111111"}, Tags=catalog_tags
    )
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=other_name))
    other = athena.get_data_catalog(Name=other_name)["DataCatalog"]
    assert other["Parameters"] == {"catalog-id": "111111111111"}


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
