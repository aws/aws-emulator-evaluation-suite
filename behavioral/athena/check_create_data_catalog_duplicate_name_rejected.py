"""create-data-catalog-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-data-catalog-duplicate-name-rejected"
GROUP = "ordering"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDataCatalog with an existing Name fails InvalidRequestException and leaves the existing
    catalog unchanged; a fresh name succeeds, and so does the same request once the original is deleted."""
    athena = ctx.client("athena")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-cat-dup-")
    tag_kv = [{"Key": "sim2real", "Value": "create-data-catalog-duplicate-name"}]
    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Description="original",
        Parameters={"catalog-id": account_id},
        Tags=tag_kv,
    )
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=name))

    original = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert original["Description"] == "original", (
        f"expected the freshly created catalog to report Description 'original', got "
        f"{original['Description']!r}"
    )

    def _duplicate_create():
        athena.create_data_catalog(
            Name=name,
            Type="GLUE",
            Description="duplicate-attempt-should-not-apply",
            Parameters={"catalog-id": account_id},
        )

    code, message = _error(_duplicate_create)
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException creating a data catalog with a Name that already "
        f"exists, got {code!r}"
    )
    assert message == f"DataCatalog {name} has already been created.", repr(message)

    # Effect-absence: the rejected duplicate request must not have mutated the existing catalog.
    after = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert after["Description"] == "original", "rejected duplicate CreateDataCatalog mutated the existing catalog"
    assert after["Type"] == "GLUE", f"expected unchanged Type 'GLUE' after the rejected duplicate, got {after['Type']!r}"

    # Restore: deleting the conflicting catalog and retrying the identical CreateDataCatalog
    # call proves the rejection was specific to the name collision, not the request shape.
    athena.delete_data_catalog(Name=name)
    delete_code, delete_message = _error(lambda: athena.get_data_catalog(Name=name))
    assert delete_code == "InvalidRequestException", (
        f"expected GetDataCatalog on a deleted catalog to raise InvalidRequestException, got "
        f"{delete_code!r}"
    )
    assert delete_message == f"DataCatalog {name} was not found.", repr(delete_message)

    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Description="recreated-after-restore",
        Parameters={"catalog-id": account_id},
        Tags=tag_kv,
    )
    restored = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert restored["Description"] == "recreated-after-restore", (
        f"expected the identical CreateDataCatalog call to succeed once the name was freed, "
        f"got Description {restored['Description']!r}"
    )

    # Positive control: the identical shape of request succeeds with a fresh, non-conflicting name.
    control_name = ctx.unique_name("sim2real-cat-dup-ctrl-")
    athena.create_data_catalog(
        Name=control_name,
        Type="GLUE",
        Description="control",
        Parameters={"catalog-id": account_id},
        Tags=tag_kv,
    )
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=control_name))
    control = athena.get_data_catalog(Name=control_name)["DataCatalog"]
    assert control["Description"] == "control", f"expected control catalog Description 'control', got {control['Description']!r}"
    assert control["Type"] == "GLUE", f"expected control catalog Type 'GLUE', got {control['Type']!r}"


def _error(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
