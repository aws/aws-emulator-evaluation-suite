"""catalog-delete-nonexistent-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "catalog-delete-nonexistent-rejected"
GROUP = "state-machine"
SERVICES = ["glue"]


def _error_code_and_message(fn):
    """Call fn(); return the AWS error (Code, Message) it raised. An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_catalog_tolerating_missing(glue, catalog_id: str) -> None:
    """Teardown delete that tolerates the catalog already being gone."""
    from botocore.exceptions import ClientError

    try:
        glue.delete_catalog(CatalogId=catalog_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "EntityNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCatalog removes a real federated catalog and fails with EntityNotFoundException 'Catalog not
    found.' for an id never created, and a plain CreateCatalog is rejected with InvalidInputException and
    creates no catalog.
    """
    glue = ctx.client("glue")
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-glue-catdel-").lower().replace("_", "-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name, tags={"sim2real": CHECK})["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn))

    control_name = ctx.unique_name("sim2real-glue-cat-").lower()
    glue.create_catalog(
        Name=control_name,
        CatalogInput={"FederatedCatalog": {"ConnectionName": "aws:s3tables", "Identifier": bucket_arn}},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_catalog_tolerating_missing(glue, control_name))

    # Positive control: DeleteCatalog on a real, existing catalog succeeds.
    glue.delete_catalog(CatalogId=control_name)
    code, message = _error_code_and_message(lambda: glue.get_catalog(CatalogId=control_name))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    expected_message = "Catalog not found."
    assert message == expected_message, (
        f"expected GetCatalog's not-found message {expected_message!r}, got {message!r}"
    )

    # Negative: a CatalogId that was never created is rejected the same way, with no side effect.
    bogus_id = ctx.unique_name("sim2real-no-such-catalog-")
    code, message = _error_code_and_message(lambda: glue.delete_catalog(CatalogId=bogus_id))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    expected_message = "Catalog not found."
    assert message == expected_message, (
        f"expected DeleteCatalog's not-found message {expected_message!r}, got {message!r}"
    )

    # Effect absent: nothing was created as a side effect of the rejected delete.
    code, message = _error_code_and_message(lambda: glue.get_catalog(CatalogId=bogus_id))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    expected_message = "Catalog not found."
    assert message == expected_message, (
        f"expected GetCatalog's not-found message {expected_message!r}, got {message!r}"
    )

    # Overly-permissive guard: a plain (non-federated) CreateCatalog is rejected with
    # InvalidInputException, and no catalog is left behind.
    name = ctx.unique_name("sim2real-catalog-")
    # if a target wrongly accepts the plain catalog, teardown removes it
    ctx.on_cleanup(lambda: _delete_catalog_tolerating_missing(glue, name))

    code, message = _error_code_and_message(
        lambda: glue.create_catalog(Name=name, CatalogInput={"Description": "control catalog"})
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code} ({message!r})"
    expected_message = "Create glue native catalog is not supported."
    assert message == expected_message, (
        f"expected CreateCatalog's native-catalog refusal message {expected_message!r}, got {message!r}"
    )
    code, message = _error_code_and_message(lambda: glue.get_catalog(CatalogId=name))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    expected_message = "Catalog not found."
    assert message == expected_message, (
        f"expected GetCatalog's not-found message {expected_message!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

