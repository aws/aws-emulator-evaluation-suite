"""op-contract-deleteDataCatalog."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteDataCatalog"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDataCatalog removes the catalog so subsequent GetDataCatalog fails,
    and deleting an unknown catalog name raises InvalidRequestException."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real_athena_cat_")
    athena.create_data_catalog(
        Name=name, Type="GLUE", Description="sim2real behavioral check",
        Parameters={"catalog-id": account_id},
    )
    created = True

    def _cleanup():
        nonlocal created
        if created:
            try:
                athena.delete_data_catalog(Name=name)
            except ClientError as exc:
                err = exc.response["Error"]
                if not (err.get("Code") == "InvalidRequestException" and "was not found" in err.get("Message", "")):
                    raise

    ctx.on_cleanup(_cleanup)

    # Confirm it exists before deleting.
    got = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert got["Type"] == "GLUE", f"expected Type GLUE on the positive control, got {got['Type']!r}"

    athena.delete_data_catalog(Name=name)
    created = False

    code, message = _error(lambda: athena.get_data_catalog(Name=name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == f"DataCatalog {name} was not found.", message

    # Error boundary: deleting the now-nonexistent catalog again is rejected too.
    code2, message2 = _error(lambda: athena.delete_data_catalog(Name=name))
    assert code2 == "InvalidRequestException", f"expected InvalidRequestException, got {code2}"
    assert message2 == f"DataCatalog {name} was not found", message2


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts what real AWS refuses never reads as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
