"""data-catalog-lambda-missing-metadata-function-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "data-catalog-lambda-missing-metadata-function-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDataCatalog of Type=LAMBDA with empty Parameters is rejected with
    InvalidRequestException and leaves no catalog behind, while a LAMBDA create with a
    function parameter succeeds (positive control), so the refusal is parameter-specific."""
    athena = ctx.client("athena")
    good_name = ctx.unique_name("sim2real-athena-cat-ok-")
    bad_name = ctx.unique_name("sim2real-athena-cat-")

    athena.create_data_catalog(
        Name=good_name,
        Type="LAMBDA",
        Parameters={
            "function": (
                f"arn:aws:lambda:{ctx.region}:123456789012:function:sim2real-behav-athena-md-fn"
            )
        },
    )
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=good_name))
    control = athena.get_data_catalog(Name=good_name)["DataCatalog"]
    assert control["Type"] == "LAMBDA", control
    assert control["Name"] == good_name, control

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            athena.delete_data_catalog(Name=bad_name)
        except ClientError as exc:
            # The rejected create leaves nothing: "DataCatalog ... was not found" is the clean case.
            if "not found" not in exc.response["Error"].get("Message", ""):
                raise

    ctx.on_cleanup(_cleanup)

    code, message = _error(
        lambda: athena.create_data_catalog(Name=bad_name, Type="LAMBDA", Parameters={})
    )
    assert code == "InvalidRequestException", code
    assert message == "Lambda catalog parameters cannot be empty.", message

    code2, message2 = _error(lambda: athena.get_data_catalog(Name=bad_name))
    assert code2 == "InvalidRequestException", code2
    assert message2 == f"DataCatalog {bad_name} was not found.", message2


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
