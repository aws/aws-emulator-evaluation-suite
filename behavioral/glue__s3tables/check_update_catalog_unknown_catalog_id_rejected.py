"""update-catalog-unknown-catalog-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-catalog-unknown-catalog-id-rejected"
GROUP = "state-machine"
SERVICES = ["glue", "s3tables"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_catalog_ignoring_not_found(glue, catalog_id):
    try:
        glue.delete_catalog(CatalogId=catalog_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCatalog on a CatalogId nobody created fails EntityNotFoundException, while the
    identical call against a real federated catalog gets past that check and is refused for its
    own, distinct and unrelated reason: a federated catalog accepts no update at all.
    """
    glue = ctx.client("glue")
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-behav-catup-").lower().replace("_", "-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name, tags={"sim2real": CHECK})["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn))

    name = ctx.unique_name("sim2real-behav-catalog-")
    original_description = "a catalog created for this check"
    glue.create_catalog(
        Name=name,
        CatalogInput={
            "Description": original_description,
            "FederatedCatalog": {"ConnectionName": "aws:s3tables", "Identifier": bucket_arn},
        },
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_catalog_ignoring_not_found(glue, name))

    missing = ctx.unique_name("sim2real-behav-catalog-missing-")
    updated_description = "a description nobody should ever see applied"
    code, message = _error(
        lambda: glue.update_catalog(
            CatalogId=missing, CatalogInput={"Description": updated_description}
        )
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}: {message!r}"
    assert message == "Catalog not found.", f"unexpected message for a missing catalog: {message!r}"

    # Effect absent: the rejected call created nothing under the missing id.
    code, message = _error(lambda: glue.get_catalog(CatalogId=missing))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}: {message!r}"
    assert message == "Catalog not found.", f"unexpected message for a missing catalog: {message!r}"

    # Positive control: the identical call against a catalog that really exists gets past
    # the not-found check and is refused for an unrelated, later reason instead.
    code, message = _error(
        lambda: glue.update_catalog(CatalogId=name, CatalogInput={"Description": updated_description})
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}: {message!r}"
    assert message == "Update on FederateCatalog is not allowed.", (
        f"unexpected InvalidInputException message: {message!r}"
    )

    # Effect absent: the refused update did not touch the real catalog's Description.
    got = glue.get_catalog(CatalogId=name)["Catalog"]
    assert got["Description"] == original_description, (
        f"a refused UpdateCatalog must not change Description; expected "
        f"{original_description!r}, got {got.get('Description')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
