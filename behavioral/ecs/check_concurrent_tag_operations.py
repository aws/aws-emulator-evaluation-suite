"""concurrent-tag-operations."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "concurrent-tag-operations"
GROUP = 'overly-permissive'
SERVICES = ['ecs']


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on one key racing UntagResource on another key of the same cluster both land:
    ListTagsForResource converges to the new value and the removed key gone. Tagging/untagging a
    nonexistent resource ARN is rejected."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    cluster = ecs.create_cluster(clusterName=name)["cluster"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    arn = cluster["clusterArn"]

    ecs.tag_resource(
        resourceArn=arn,
        tags=[
            {"key": "race-a", "value": "initial"},
            {"key": "race-b", "value": "initial"},
        ],
    )
    _poll_until(
        lambda: {t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=arn)["tags"]},
        lambda tm: tm.get("race-a") == "initial" and tm.get("race-b") == "initial",
        timeout_s=30,
        interval_s=2,
        description="the two pre-seeded tags become visible",
    )

    bogus_arn = arn.rsplit("/", 1)[0] + "/" + ctx.unique_name("no-such-cluster-")
    code, message = _error(
        lambda: ecs.tag_resource(resourceArn=bogus_arn, tags=[{"key": "x", "value": "y"}])
    )
    assert code == "ClusterNotFoundException", (
        f"expected a not-found rejection tagging a nonexistent resource, got {code}"
    )
    assert message == "Cluster not found.", f"TagResource: unexpected message {message!r}"
    code, message = _error(lambda: ecs.untag_resource(resourceArn=bogus_arn, tagKeys=["x"]))
    assert code == "ClusterNotFoundException", (
        f"expected a not-found rejection untagging a nonexistent resource, got {code}"
    )
    assert message == "Cluster not found.", f"UntagResource: unexpected message {message!r}"

    def _update_a():
        return ecs.tag_resource(resourceArn=arn, tags=[{"key": "race-a", "value": "updated"}])

    def _remove_b():
        return ecs.untag_resource(resourceArn=arn, tagKeys=["race-b"])

    results = _run_concurrent([_update_a, _remove_b], timeout_s=30)
    successes = _concurrent_successes(results)
    assert successes == 2, (
        f"expected both the concurrent TagResource and UntagResource calls to succeed, got "
        f"{successes}/2 (codes: {_concurrent_error_codes(results)})"
    )

    final_tags = _poll_until(
        lambda: {t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=arn)["tags"]},
        lambda tm: tm.get("race-a") == "updated" and "race-b" not in tm,
        timeout_s=30,
        interval_s=2,
        description="the tag set converges to reflect BOTH the update and the removal",
    )
    assert final_tags.get("race-a") == "updated", (
        f"expected race-a to converge to 'updated', got {final_tags.get('race-a')}"
    )
    assert "race-b" not in final_tags, f"expected race-b to be genuinely removed, got {final_tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
