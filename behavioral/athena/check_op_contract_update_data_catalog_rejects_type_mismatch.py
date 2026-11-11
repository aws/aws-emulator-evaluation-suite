"""op-contract-update-data-catalog-rejects-type-mismatch."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-update-data-catalog-rejects-type-mismatch"
GROUP = "error-semantics"
SERVICES = ["athena"]


def _error(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDataCatalog updates Description for a matching Type, but a GLUE -> LAMBDA update with
    only "metadata-function" fails with InvalidRequestException and leaves the catalog unchanged."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-catalog-")
    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Description="initial description",
        Parameters={"catalog-id": account_id},
    )
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=name))

    before = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert before["Type"] == "GLUE", before
    assert before["Description"] == "initial description", before

    athena.update_data_catalog(
        Name=name,
        Type="GLUE",
        Description="updated description",
        Parameters={"catalog-id": account_id},
    )
    after_valid_update = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert after_valid_update["Description"] == "updated description", after_valid_update

    lambda_arn = f"arn:aws:lambda:{ctx.region}:{account_id}:function:sim2real-nonexistent"
    code, message = _error(
        lambda: athena.update_data_catalog(
            Name=name,
            Type="LAMBDA",
            Description="migrated to lambda type",
            # A LAMBDA catalog takes "metadata-function" together with
            # "record-function", or the single "function" key; one of the pair
            # alone is refused.
            Parameters={"metadata-function": lambda_arn},
        )
    )
    assert code == "InvalidRequestException", (
        f"expected the Type-changing update to be rejected with InvalidRequestException, got {code}"
    )
    expected_message = (
        "Lambda catalogs require that either the metadata-function and record-function "
        "parameters or the function parameter be set, but not both."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    after_rejected_change = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert after_rejected_change["Type"] == "GLUE", f"expected Type GLUE, got {after_rejected_change['Type']}"
    assert after_rejected_change["Description"] == "updated description", after_rejected_change
    assert after_rejected_change["Parameters"].get("catalog-id") == account_id, after_rejected_change
    assert "metadata-function" not in after_rejected_change["Parameters"], after_rejected_change


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
