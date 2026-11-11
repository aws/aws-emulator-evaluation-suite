"""concurrent-catalog-create-conflict-detected."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-catalog-create-conflict-detected"
GROUP = "concurrency"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of 8 racing CreateCatalog calls for one new name at most one succeeds and the others are refused with
    AlreadyExistsException, FederatedResourceAlreadyExistsException or ConcurrentModificationException 'Resource
    being modified concurrently.'; the catalog then exists under that name.
    """
    glue = ctx.client("glue")
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-cat-").lower().replace("_", "-")
    bucket_arn = s3tables.create_table_bucket(
        name=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn)))

    name = ctx.unique_name("sim2real-cat-")
    ctx.on_cleanup(lambda: _safe_call(lambda: glue.delete_catalog(CatalogId=name)))

    def make_call():
        def _call():
            return glue.create_catalog(
                Name=name,
                CatalogInput={
                    "Description": "race target",
                    "FederatedCatalog": {"ConnectionName": "aws:s3tables", "Identifier": bucket_arn},
                },
                Tags={"sim2real": CHECK},
            )

        return _call

    racers = 8
    outcomes = _race([make_call() for _ in range(racers)])

    successes = [o for o in outcomes if o["error"] is None]
    failures = [o for o in outcomes if o["error"] is not None]
    assert len(failures) >= 1, "no contention was ever detected among 8 simultaneous creators"
    for f in failures:
        assert f["error"] in (
            "AlreadyExistsException",
            "FederatedResourceAlreadyExistsException",
            "ConcurrentModificationException",
        ), f["error"]
        if f["error"] == "ConcurrentModificationException":
            assert f["message"] == "Resource being modified concurrently.", f["message"]
    assert len(successes) <= 1, f"more than one racer believed it created the catalog: {outcomes}"

    if not successes:
        # Every attempt lost to contention: a follow-up create must still succeed once contention clears. Retry
        # with backoff, as even a lone create can collide right after a burst of contention.
        _retry_create_catalog(make_call)

    # the catalog that did get created is real and usable, not a phantom of a lost race, and
    # there is exactly one of it
    cat = glue.get_catalog(CatalogId=name)["Catalog"]
    assert cat["Name"] == name, f"expected the winning catalog Name to be {name!r}, got {cat!r}"


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFoundException", "NotFoundException"):
            raise


def _retry_create_catalog(make_call, attempts: int = 6) -> None:
    """CreateCatalog can still transiently collide with ConcurrentModificationException /
    *AlreadyExistsException right after a burst of contention settles, even for a lone,
    non-racing caller. Retry with backoff - bounded, not a bare sleep-and-hope - until it
    lands or attempts run out."""
    import time

    delay = 0.5
    last_err = None
    for _ in range(attempts):
        try:
            make_call()()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AlreadyExistsException", "FederatedResourceAlreadyExistsException"):
                # the catalog exists (created by some other path) - the desired end state
                # is reached, nothing left to retry
                return
            if code != "ConcurrentModificationException":
                raise
            last_err = e
            time.sleep(delay)
            delay = min(delay * 2, 5)
    raise last_err


def _race(calls: list) -> list:
    n = len(calls)
    barrier = threading.Barrier(n)
    outcomes: list = [None] * n

    def worker(i: int, fn) -> None:
        barrier.wait()
        try:
            outcomes[i] = {"result": fn(), "error": None}
        except ClientError as e:
            outcomes[i] = {
                "result": None,
                "error": e.response["Error"]["Code"],
                "message": e.response["Error"].get("Message"),
            }

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(worker, i, fn) for i, fn in enumerate(calls)]
        for f in futures:
            f.result()
    return outcomes


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
