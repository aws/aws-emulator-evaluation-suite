"""concurrent-delete-catalog-conflict-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-delete-catalog-conflict-rejected"
GROUP = "concurrency"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCatalog removes a real federated catalog, while two concurrent DeleteCatalog calls on the
    account's root catalog fail with the same error and message and the root catalog stays retrievable.
    """
    glue = ctx.client("glue")
    s3tables = ctx.client("s3tables")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: DeleteCatalog genuinely works against a real, deletable catalog.
    bucket_name = ctx.unique_name("sim2real-behav-cdc-").lower().replace("_", "-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn)))

    control_name = ctx.unique_name("sim2real-behav-cdc-catalog-")
    glue.create_catalog(
        Name=control_name,
        CatalogInput={
            "Description": "sim2real behavioral fidelity check catalog (positive control)",
            "FederatedCatalog": {"ConnectionName": "aws:s3tables", "Identifier": bucket_arn},
        },
    )
    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_catalog(CatalogId=control_name)))

    got = glue.get_catalog(CatalogId=control_name)["Catalog"]
    assert got["Name"] == control_name, got

    glue.delete_catalog(CatalogId=control_name)
    control_error = _error(lambda: glue.get_catalog(CatalogId=control_name))
    assert control_error == ("EntityNotFoundException", "Catalog not found."), (
        f"positive control failed: expected the just-deleted catalog to 404, got {control_error}"
    )

    def _delete():
        return glue.delete_catalog(CatalogId=account_id)

    results = _race([_delete, _delete])
    errors = [e for _, e in results]
    assert all(e is not None for e in errors), (
        f"expected both concurrent DeleteCatalog calls against the root catalog to be "
        f"rejected, got {results}"
    )
    assert errors[0] == errors[1], f"racers disagreed on the rejection under contention: {errors}"
    assert errors[0] == (
        "InvalidInputException",
        "Only lowercase letters, numbers, underscores and hyphens are allowed for catalog name",
    ), errors

    # Effect absent under contention: the root catalog is still there, unharmed by either racer.
    still_there = glue.get_catalog(CatalogId=account_id)["Catalog"]
    assert still_there["CatalogId"] == account_id or still_there.get("Name") == account_id, still_there


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises: real AWS refuses it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")


def _ignore_missing(fn):
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("EntityNotFoundException", "NotFoundException", "NoSuchTableBucket"):
            raise


def _race(fns):
    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(fn) for fn in fns]
        results = []
        for fut in futures:
            try:
                results.append((fut.result(), None))
            except ClientError as exc:
                err = exc.response.get("Error", {})
                results.append((None, (err.get("Code"), err.get("Message"))))
    return results


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
