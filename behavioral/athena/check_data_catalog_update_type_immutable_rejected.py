"""data-catalog-update-type-immutable-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "data-catalog-update-type-immutable-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateDataCatalog changing a GLUE catalog's Type to LAMBDA fails InvalidRequestException and
    the stored Type is unchanged; the same call with the original Type succeeds."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-athena-cat-")
    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": "data-catalog-update-type-immutable-rejected"}],
    )
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=name))

    code, message = _error_code(
        lambda: athena.update_data_catalog(
            Name=name,
            Type="LAMBDA",
            Parameters={"metadata-function": "arn:aws:lambda:us-east-1:111122223333:function:x"},
        )
    )
    assert code == "InvalidRequestException", code
    assert message == "Lambda catalogs require that either the metadata-function and record-function parameters or the function parameter be set, but not both.", (
        f"expected the exact InvalidRequestException message AWS returns, got {message!r}"
    )

    unchanged = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert unchanged["Type"] == "GLUE", unchanged

    # Positive control: updating with the original, matching Type succeeds.
    athena.update_data_catalog(
        Name=name, Type="GLUE", Description="updated description", Parameters={"catalog-id": account_id}
    )
    still_glue = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert still_glue["Type"] == "GLUE", f"expected Type GLUE after a matching-Type update, got {still_glue['Type']}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
