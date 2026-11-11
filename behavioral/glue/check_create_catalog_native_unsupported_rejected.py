"""create-catalog-native-unsupported-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-catalog-native-unsupported-rejected"
GROUP = "negative-classes"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A plain CreateCatalog is rejected twice with InvalidInputException 'Create glue native catalog is not
    supported.' and GetCatalog then fails with EntityNotFoundException 'Catalog not found.', while the root
    catalog is readable.
    """
    glue = ctx.client("glue")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-cat-")
    catalog_input = {"Description": "sim2real duplicate-name negative check"}

    # Positive control: the account and credentials are otherwise healthy for
    # Glue -- the root catalog (CatalogId == account id) is always readable,
    # so a rejection below is the service's contract, not a broken caller.
    root = glue.get_catalog(CatalogId=account_id)["Catalog"]
    assert root["CatalogId"] == account_id, f"expected root catalog {account_id!r}, got {root.get('CatalogId')!r}"

    code, message = _error(lambda: glue.create_catalog(Name=name, CatalogInput=catalog_input))
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code!r} ({message!r})"
    assert message == "Create glue native catalog is not supported.", (
        f"unexpected message for rejected native catalog: {message!r}"
    )

    # Effect absent: the rejected create did not actually create a catalog
    # under this Name.
    not_found_code, not_found_message = _error(lambda: glue.get_catalog(CatalogId=name))
    assert not_found_code == "EntityNotFoundException", f"expected EntityNotFoundException, got {not_found_code!r}"
    assert not_found_message == "Catalog not found.", f"unexpected GetCatalog message: {not_found_message!r}"

    # Repeat: the rejection is deterministic, not a one-off transient error --
    # calling it again with the exact same input is rejected the same way.
    code_2, message_2 = _error(lambda: glue.create_catalog(Name=name, CatalogInput=catalog_input))
    assert code_2 == "InvalidInputException", f"expected InvalidInputException on repeat, got {code_2!r} ({message_2!r})"
    assert message_2 == "Create glue native catalog is not supported.", f"unexpected message on repeat: {message_2!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
