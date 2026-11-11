"""concurrent-tag-resource-no-lost-updates."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-tag-resource-no-lost-updates"
GROUP = "concurrency"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """Firing several concurrent TagResource calls, each adding a distinct key to the same
    graph, must not lose any writes: every key must be present afterwards."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    keys = [f"sim2real-detective-concurrent-{i}" for i in range(8)]
    ctx.on_cleanup(lambda: _untag_quietly(d, arn, keys))

    def _tag_one(i: int) -> None:
        d.tag_resource(ResourceArn=arn, Tags={keys[i]: str(i)})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_tag_one, range(8)))

    final = _poll_until(
        probe=lambda: d.list_tags_for_resource(ResourceArn=arn)["Tags"],
        predicate=lambda tags: all(k in tags for k in keys),
        timeout_s=30.0,
        interval_s=2.0,
    )
    for i, key in enumerate(keys):
        assert final.get(key) == str(i), f"expected tag {key!r}={i!r}, got {final.get(key)!r} (all tags: {final!r})"


def _create_graph_with_retry(d, retries: int = 8, base_delay: float = 5.0) -> str:
    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            return d.create_graph()["GraphArn"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < retries - 1:
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise AssertionError("create_graph did not succeed after retries")


def _untag_quietly(d, graph_arn: str, keys: list[str]) -> None:
    from botocore.exceptions import ClientError

    try:
        d.untag_resource(ResourceArn=graph_arn, TagKeys=keys)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
