"""concurrent-delete-filter-exactly-one-succeeds."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-delete-filter-exactly-one-succeeds"
GROUP = "concurrency"
SERVICES = ["inspector2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent DeleteFilter calls on the same filter both succeed and neither returns
    ResourceNotFoundException: DeleteFilter is idempotent under concurrency."""
    inspector2 = ctx.client("inspector2")
    name = ctx.unique_name("sim2real-filter-race-")

    created = inspector2.create_filter(
        action="NONE",
        name=name,
        filterCriteria={"severity": [{"comparison": "EQUALS", "value": "HIGH"}]},
        tags={"sim2real:managed": "true"},
    )
    arn = created["arn"]

    def _attempt_delete():
        try:
            inspector2.delete_filter(arn=arn)
            return "ok"
        except Exception as e:  # noqa: BLE001 - classify below
            from botocore.exceptions import ClientError

            if isinstance(e, ClientError):
                return e.response["Error"]["Code"]
            raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _attempt_delete(), range(2)))

    successes = [r for r in results if r == "ok"]
    not_found = [r for r in results if r == "ResourceNotFoundException"]
    assert len(successes) == 2, f"expected both concurrent deletes to succeed idempotently, got results={results}"
    assert not not_found, (
        f"DeleteFilter must not surface ResourceNotFoundException under concurrent idempotent delete, got {results}"
    )

    # Final state: the filter is gone once the deletion has fully propagated.
    def _final_cleanup():
        try:
            inspector2.delete_filter(arn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_final_cleanup)

    _poll_until(
        lambda: arn not in _all_filter_arns(inspector2),
        lambda gone: gone,
        timeout_s=60,
        interval_s=3,
    )


def _all_filter_arns(inspector2) -> set[str]:
    arns: set[str] = set()
    next_token = None
    while True:
        kwargs = {"maxResults": 50}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = inspector2.list_filters(**kwargs)
        for f in resp.get("filters", []):
            arns.add(f["arn"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return arns


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={value!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

