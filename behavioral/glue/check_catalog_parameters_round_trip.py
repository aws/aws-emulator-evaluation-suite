"""catalog-parameters-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "catalog-parameters-round-trip"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCatalog returns the exact Parameters map CreateCatalog set, including a key with an empty value, and
    no key that was never set.
    """
    glue = ctx.client("glue")
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-behav-catparam-").lower().replace("_", "-")
    bucket_arn = s3tables.create_table_bucket(
        name=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-catparam"},
    )["arn"]
    ctx.on_cleanup(lambda: _delete_table_bucket_ignore_missing(s3tables, bucket_arn))

    catalog_name = ctx.unique_name("sim2real-cat-").lower()
    parameters = {
        "owner": "data-platform-team",
        "empty-value-param": "",
        "environment": "sim2real-behavioral-test",
        "unicode-param": "café 日本語 🎉",
    }

    glue.create_catalog(
        Name=catalog_name,
        CatalogInput={
            "Description": "sim2real behavioral fidelity round-trip test catalog",
            "FederatedCatalog": {"ConnectionName": "aws:s3tables", "Identifier": bucket_arn},
            "Parameters": parameters,
        },
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_catalog_ignore_missing(glue, catalog_name))

    fetched = glue.get_catalog(CatalogId=catalog_name)["Catalog"]

    assert fetched["Parameters"] == parameters, (
        f"Parameters mismatch: {fetched['Parameters']!r} != {parameters!r}"
    )
    assert fetched["Parameters"]["empty-value-param"] == "", (
        f"expected empty-value-param to round-trip as '', got {fetched['Parameters'].get('empty-value-param')!r}"
    )
    assert "never-set-param" not in fetched["Parameters"], (
        f"never-set-param should be absent, got {fetched['Parameters'].get('never-set-param')!r}"
    )


def _delete_catalog_ignore_missing(glue, name: str) -> None:
    try:
        glue.delete_catalog(CatalogId=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _delete_table_bucket_ignore_missing(s3tables, bucket_arn: str) -> None:
    try:
        s3tables.delete_table_bucket(tableBucketARN=bucket_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NotFoundException", "NoSuchTableBucket"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
