"""attach-detach-data-source-race-converges-consistent."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "attach-detach-data-source-race-converges-consistent"
GROUP = "concurrency"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent AttachDataSource/DetachDataSource calls on the same (application, data source)
    pair converge to at most one consistent attachment entry -- never duplicates -- regardless of
    which racer's outcome ultimately wins."""
    opensearch = ctx.client("opensearch")
    app_id = _create_active_application(ctx)
    data_source_arn = _glue_catalog_arn(ctx)
    ctx.on_cleanup(lambda: _try_detach(ctx, app_id, data_source_arn))

    def _attach():
        return opensearch.attach_data_source(id=app_id, dataSourceArn=data_source_arn)

    def _detach():
        return opensearch.detach_data_source(id=app_id, dataSourceArn=data_source_arn)

    results: list[tuple[str, object]] = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            pool.submit(_attach): "attach-1",
            pool.submit(_attach): "attach-2",
            pool.submit(_detach): "detach-1",
            pool.submit(_detach): "detach-2",
        }
        for future, label in futures.items():
            try:
                results.append((label, ("ok", future.result())))
            except Exception as exc:  # noqa: BLE001 - captured, not asserted on individually
                results.append((label, ("error", exc)))

    # wait for the async attachment state machine (PENDING -> ATTACHED/FAILED) to settle:
    # two consecutive identical observations, not a fixed sleep, since the transition has
    # no guaranteed latency.
    matching = _poll_until_settled(opensearch, app_id, data_source_arn)
    assert len(matching) <= 1, (
        f"expected at most one attachment entry for {data_source_arn} after racing "
        f"attach/detach, got {len(matching)}: {matching!r} (racers: {results!r})"
    )
    if matching:
        assert matching[0]["status"] in ("PENDING", "ATTACHED"), (
            f"lingering attachment is in an unexpected status: {matching[0]!r}"
        )


def _glue_catalog_arn(ctx) -> str:
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    return f"arn:aws:glue:{ctx.region}:{account}:catalog"


def _poll_until_settled(
    opensearch, app_id: str, data_source_arn: str, timeout_s: float = 120.0, interval_s: float = 3.0
) -> list[dict]:
    """Poll list_data_source_attachments until the matching entries for data_source_arn are
    identical (by status) across two consecutive observations -- the freeze-detector pattern,
    since the PENDING -> ATTACHED/FAILED transition carries no guaranteed latency."""
    deadline = time.monotonic() + timeout_s
    previous: tuple[str, ...] | None = None
    matching: list[dict] = []
    while time.monotonic() < deadline:
        attachments = opensearch.list_data_source_attachments(id=app_id)["attachments"]
        matching = [a for a in attachments if a["dataSourceArn"] == data_source_arn]
        current = tuple(sorted(a["status"] for a in matching))
        if current == previous:
            return matching
        previous = current
        time.sleep(interval_s)
    raise AssertionError(
        f"attachment state for {data_source_arn} never settled within {timeout_s}s "
        f"(last observation={previous})"
    )


def _try_detach(ctx, app_id: str, data_source_arn: str) -> None:
    opensearch = ctx.client("opensearch")
    try:
        opensearch.detach_data_source(id=app_id, dataSourceArn=data_source_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_active_application(ctx, timeout_s: float = 120.0) -> str:
    opensearch = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-osapp-").replace("_", "-").lower()[:30]
    resp = opensearch.create_application(name=name, tagList=[{"Key": "sim2real", "Value": "audit"}])
    app_id = resp["id"]
    ctx.on_cleanup(lambda: opensearch.delete_application(id=app_id))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.get_application(id=app_id)["status"]
        if status == "ACTIVE":
            return app_id
        if status == "FAILED":
            raise AssertionError(f"application {app_id} failed to become ACTIVE")
        time.sleep(3)
    raise AssertionError(f"application {app_id} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
