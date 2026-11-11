"""data-catalog-type-mismatch-update-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "data-catalog-type-mismatch-update-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDataCatalog switching a GLUE catalog to LAMBDA fails InvalidRequestException and the Type
    stays GLUE, while a same-Type update succeeds."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-athena-cat-")

    athena.create_data_catalog(
        Name=name, Type="GLUE", Description="initial", Parameters={"catalog-id": account_id}
    )
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=name))

    # Positive control: a same-Type update succeeds, proving UpdateDataCatalog works
    # on this catalog at all before the Type-changing call is tried.
    athena.update_data_catalog(
        Name=name, Type="GLUE", Description="updated", Parameters={"catalog-id": account_id}
    )
    after_valid = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert after_valid["Description"] == "updated", after_valid

    code, message = _error_code(
        lambda: athena.update_data_catalog(
            Name=name,
            Type="LAMBDA",
            Description="migrated",
            Parameters={"metadata-function": f"arn:aws:lambda:{ctx.region}:{account_id}:function:does-not-exist"},
        )
    )
    assert code == "InvalidRequestException", code
    assert message == "Lambda catalogs require that either the metadata-function and record-function parameters or the function parameter be set, but not both.", (
        f"expected the exact InvalidRequestException message AWS returns, got {message!r}"
    )

    got = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert got["Type"] == "GLUE", got["Type"]
    assert got["Description"] == "updated", got["Description"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
