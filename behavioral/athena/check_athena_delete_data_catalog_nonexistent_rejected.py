"""athena-delete-data-catalog-nonexistent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "athena-delete-data-catalog-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDataCatalog for a Name that was never created is rejected with InvalidRequestException.
    A positive control creates, confirms and deletes a real catalog first, so the rejection is shown
    to be about the unknown name -- not about DeleteDataCatalog being refused wholesale."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: create, confirm, and delete a real catalog.
    real_name = ctx.unique_name("sim2real-athena-cat-real-")
    athena.create_data_catalog(Name=real_name, Type="GLUE", Parameters={"catalog-id": account_id})
    created = True

    def _cleanup():
        nonlocal created
        if created:
            try:
                athena.delete_data_catalog(Name=real_name)
            except ClientError as exc:
                if "not found" not in exc.response["Error"].get("Message", ""):
                    raise

    ctx.on_cleanup(_cleanup)

    assert athena.get_data_catalog(Name=real_name)["DataCatalog"]["Status"] == "CREATE_COMPLETE"
    athena.delete_data_catalog(Name=real_name)
    created = False

    code, message = _expect_error(
        lambda: athena.get_data_catalog(Name=real_name),
        "GetDataCatalog on the just-deleted catalog",
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == f"DataCatalog {real_name} was not found.", message

    code, message = _expect_error(
        lambda: athena.delete_data_catalog(Name=real_name),
        "second DeleteDataCatalog on the already-deleted catalog",
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == f"DataCatalog {real_name} was not found", message

    # The actual subject: a name that was never created at all.
    bogus_name = ctx.unique_name("sim2real-athena-cat-missing-")

    code, message = _expect_error(
        lambda: athena.delete_data_catalog(Name=bogus_name),
        "DeleteDataCatalog on a nonexistent catalog",
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == f"DataCatalog {bogus_name} was not found", message

    code, message = _expect_error(
        lambda: athena.get_data_catalog(Name=bogus_name),
        "GetDataCatalog on a nonexistent catalog",
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == f"DataCatalog {bogus_name} was not found.", message


def _expect_error(fn, description):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises,
    because accepting a call AWS refuses must not read as a mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {description} to raise, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
