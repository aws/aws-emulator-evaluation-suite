"""concurrent-catalog-create-conflict-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-catalog-create-conflict-rejected"
GROUP = "concurrency"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent plain CreateCatalog calls for one name both fail with the same InvalidInputException,
    never a ConcurrentModificationException, and leave no catalog, while a federated CreateCatalog succeeds.
    """
    glue = ctx.client("glue")
    s3tables = ctx.client("s3tables")

    # Positive control: an S3 Tables-federated CreateCatalog succeeds, so the rejection below is not a blanket
    # denial.
    bucket_name = ctx.unique_name("sim2real-catraceok-").lower().replace("_", "-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn)))

    control_name = ctx.unique_name("sim2real-catraceok-")
    glue.create_catalog(
        Name=control_name,
        CatalogInput={
            "Description": "positive control for concurrent-catalog-create-conflict-rejected",
            "FederatedCatalog": {"ConnectionName": "aws:s3tables", "Identifier": bucket_arn},
        },
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: glue.delete_catalog(CatalogId=control_name)))
    control = glue.get_catalog(CatalogId=control_name)["Catalog"]
    assert control["Name"] == control_name

    # Break exactly one thing: both racers share the same Name AND an always-invalid, plain
    # (non-federated) CatalogInput.
    name = ctx.unique_name("sim2real-catalog-createrace-")

    def _create():
        return glue.create_catalog(Name=name, CatalogInput={})

    results = _race([_create, _create])
    errors = [e for _, e in results]
    plain_refusal = ("InvalidInputException", "Create glue native catalog is not supported.")
    assert errors == [plain_refusal, plain_refusal], (
        f"expected both concurrent plain-CatalogInput creates to fail identically with "
        f"InvalidInputException (validation precedes any name lock), got {results}"
    )

    # Effect absent: neither racer left a catalog behind under this name.
    gone = _error(lambda: glue.get_catalog(CatalogId=name))
    assert gone == ("EntityNotFoundException", "Catalog not found."), gone


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises: real AWS refuses it."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFoundException", "NotFoundException"):
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
