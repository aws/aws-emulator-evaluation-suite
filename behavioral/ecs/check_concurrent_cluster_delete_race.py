"""concurrent-cluster-delete-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-cluster-delete-race"
GROUP = "concurrency"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent DeleteCluster calls converge on one INACTIVE cluster with no undefined middle state."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx, ecs)
    arn = cluster["clusterArn"]
    n = 5

    def delete(_i):
        return ecs.delete_cluster(cluster=arn)

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(delete, i) for i in range(n)]
        n_success = 0
        codes = []
        for f in futures:
            try:
                f.result()
                n_success += 1
            except Exception as exc:  # noqa: BLE001
                codes.append(getattr(exc, "response", {}).get("Error", {}).get("Code"))

    # At least one caller must win; losers may only lose in a well-defined way.
    assert n_success >= 1, codes
    assert n_success + len(codes) == n, (n_success, codes)
    allowed = {
        "ClusterNotFoundException",
        "InvalidParameterException",
        "ClusterContainsTasksException",
        "ClusterContainsServicesException",
        "ThrottlingException",
        "UpdateInProgressException",
    }
    assert set(codes) <= allowed, codes

    # Whoever won, the terminal state is a single INACTIVE cluster.
    final = _poll_until(
        lambda: ecs.describe_clusters(clusters=[arn])["clusters"],
        lambda cs: bool(cs) and cs[0]["status"] == "INACTIVE",
        timeout_s=90,
        interval_s=5,
        description=f"cluster {arn} to settle at INACTIVE",
    )
    assert final[0]["status"] == "INACTIVE", final


# Codes that mean "the control plane is busy", never "your request was wrong".
_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "RequestLimitExceeded",
    "TooManyRequestsException",
)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _retry_throttled(fn, attempts: int = 7, base_delay: float = 2.0):
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(min(base_delay * (2**i), 20.0))
    raise last


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _create_cluster(ctx, ecs, name=None, **kwargs) -> dict:
    """Create a cluster with a best-effort teardown.

    The racers below delete this cluster themselves; the registered teardown is a
    safety net for a mid-check failure and is a harmless no-op (ClusterNotFound)
    once the race has already driven it INACTIVE.
    """
    name = name or ctx.unique_name("sim2real-behav-ecs-cluster-")
    kwargs.setdefault("tags", [{"key": "sim2real", "value": "true"}])
    resp = _retry_throttled(lambda: ecs.create_cluster(clusterName=name, **kwargs))
    arn = resp["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ecs.delete_cluster(cluster=arn)))
    return resp["cluster"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
