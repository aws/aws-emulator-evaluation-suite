"""data-catalog-lambda-type-missing-required-parameter-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "data-catalog-lambda-type-missing-required-parameter-fails"
GROUP = 'overly-permissive'
SERVICES = ['athena']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDataCatalog(Type=LAMBDA) without its required function parameters fails and leaves no
    catalog, while the same call with metadata-function and record-function ARNs succeeds
    (positive control), so the rejection is specific to the missing parameter."""
    athena = ctx.client("athena")

    control_name = ctx.unique_name("sim2real-behav-catalog-ctrl-")
    athena.create_data_catalog(
        Name=control_name,
        Type="LAMBDA",
        # LAMBDA catalogs require BOTH metadata-function and record-function together
        # (or "function" alone) — metadata-function by itself is rejected.
        Parameters={
            "metadata-function": f"arn:aws:lambda:{ctx.region}:123456789012:function:sim2real-does-not-exist-metadata",
            "record-function": f"arn:aws:lambda:{ctx.region}:123456789012:function:sim2real-does-not-exist-record",
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(athena, control_name))
    control = athena.get_data_catalog(Name=control_name)["DataCatalog"]
    assert control["Type"] == "LAMBDA", f"expected control catalog Type LAMBDA, got {control['Type']!r}"

    name = ctx.unique_name("sim2real-behav-catalog-")
    # registered before the create so an unexpected success never leaks a catalog
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(athena, name))
    code, message = _error(
        lambda: athena.create_data_catalog(
            Name=name,
            Type="LAMBDA",
            Parameters={},  # missing required metadata-function ARN
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "Lambda catalog parameters cannot be empty.", message

    # must not have been left behind as a half-created catalog
    code2, message2 = _error(lambda: athena.get_data_catalog(Name=name))
    assert code2 == "InvalidRequestException", (
        f"expected GetDataCatalog({name!r}) to fail with InvalidRequestException after the "
        f"failed create, got {code2}"
    )
    assert message2 == f"DataCatalog {name} was not found.", message2


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


def _delete_ignoring_not_found(athena, name):
    from botocore.exceptions import ClientError

    try:
        athena.delete_data_catalog(Name=name)
    except ClientError as exc:
        if "not found" not in exc.response["Error"].get("Message", ""):
            raise

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
