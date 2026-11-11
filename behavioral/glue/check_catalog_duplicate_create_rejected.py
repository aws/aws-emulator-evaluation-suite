"""catalog-duplicate-create-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "catalog-duplicate-create-rejected"
GROUP = "state-machine"
SERVICES = ["glue"]

_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


def _federated_input(bucket_arn: str, description: str) -> dict:
    return {
        "Description": description,
        "FederatedCatalog": {"ConnectionName": "aws:s3tables", "Identifier": bucket_arn},
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCatalog with a Name in use is rejected with AlreadyExistsException and its exact message and leaves the
    original Description unchanged; once the original is deleted the same call succeeds with its new Description.
    """
    glue = ctx.client("glue")
    s3tables = ctx.client("s3tables")
    bucket_name = ctx.unique_name("sim2real-behav-catdup-").lower().replace("_", "-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name, tags=_TAGS)["arn"]
    ctx.on_cleanup(lambda: _delete_table_bucket_ignore_missing(s3tables, bucket_arn))

    name = ctx.unique_name("sim2real-behav-catalog-dup-")
    original_description = "original catalog description"

    glue.create_catalog(
        Name=name, CatalogInput=_federated_input(bucket_arn, original_description), Tags=_TAGS
    )
    ctx.on_cleanup(lambda: _delete_catalog_ignore_missing(glue, name))

    # Positive control: the original catalog was actually created with our description.
    original = glue.get_catalog(CatalogId=name)["Catalog"]
    assert original["Description"] == original_description, (
        f"expected freshly-created catalog Description={original_description!r}, "
        f"got {original.get('Description')!r}"
    )

    # Break exactly one thing: try to create a second catalog with the same Name.
    conflicting_input = _federated_input(bucket_arn, "a completely different description")
    code, message = _error(
        lambda: glue.create_catalog(Name=name, CatalogInput=conflicting_input, Tags=_TAGS)
    )
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code!r}"
    expected_message = "Catalog already exists"
    assert message == expected_message, (
        f"expected CreateCatalog's duplicate-name message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the original catalog's attributes were not overwritten by the rejected call.
    got = glue.get_catalog(CatalogId=name)["Catalog"]
    assert got["Description"] == original_description, (
        f"rejected CreateCatalog must not overwrite the original; expected "
        f"Description={original_description!r}, got {got.get('Description')!r}"
    )

    # Restore: lift the Name conflict; the identical call that just failed then succeeds.
    glue.delete_catalog(CatalogId=name)
    gone_code, gone_message = _error(lambda: glue.get_catalog(CatalogId=name))
    assert gone_code == "EntityNotFoundException", (
        f"expected the catalog to be gone after DeleteCatalog, got {gone_code!r}"
    )
    expected_gone = "Catalog not found."
    assert gone_message == expected_gone, (
        f"expected GetCatalog's not-found message {expected_gone!r}, got {gone_message!r}"
    )

    glue.create_catalog(Name=name, CatalogInput=conflicting_input, Tags=_TAGS)
    restored = glue.get_catalog(CatalogId=name)["Catalog"]
    assert restored["Description"] == "a completely different description", (
        "identical CreateCatalog call must succeed once the Name conflict is lifted; "
        f"got Description={restored.get('Description')!r}"
    )

    # Positive control: creating a catalog with a distinct Name succeeds in the same file.
    # A federation target (bucket ARN) can only be claimed by one catalog at a time, so this
    # needs its own bucket rather than reusing the first catalog's.
    other_bucket_name = ctx.unique_name("sim2real-behav-catdupother-").lower().replace("_", "-")
    other_bucket_arn = s3tables.create_table_bucket(name=other_bucket_name, tags=_TAGS)["arn"]
    ctx.on_cleanup(lambda: _delete_table_bucket_ignore_missing(s3tables, other_bucket_arn))

    other_name = ctx.unique_name("sim2real-behav-catalog-dup-other-")
    glue.create_catalog(
        Name=other_name,
        CatalogInput=_federated_input(other_bucket_arn, "unique catalog"),
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_catalog_ignore_missing(glue, other_name))
    other = glue.get_catalog(CatalogId=other_name)["Catalog"]
    assert other["Name"] == other_name, f"expected Name={other_name!r}, got {other.get('Name')!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore Error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_catalog_ignore_missing(glue, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        glue.delete_catalog(CatalogId=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _delete_table_bucket_ignore_missing(s3tables, bucket_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        s3tables.delete_table_bucket(tableBucketARN=bucket_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NotFoundException", "NoSuchTableBucket"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
