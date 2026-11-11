"""dedicated-ip-pool-scaling-concurrent-modification-converges-to-managed."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dedicated-ip-pool-scaling-concurrent-modification-converges-to-managed"
GROUP = "concurrency"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent STANDARD->MANAGED PutDedicatedIpPoolScalingAttributes calls: one or both win,
    any loser fails with ConcurrentModificationException, and the pool converges to MANAGED."""
    sesv2 = ctx.client("sesv2")
    pool_name = ctx.unique_name("sim2real-dip-pool-")
    sesv2.create_dedicated_ip_pool(
        PoolName=pool_name,
        ScalingMode="STANDARD",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _retry_delete_pool(sesv2, pool_name))

    before = sesv2.get_dedicated_ip_pool(PoolName=pool_name)["DedicatedIpPool"]
    assert before["ScalingMode"] == "STANDARD", (
        f"expected freshly-created pool to start STANDARD, got {before['ScalingMode']}"
    )

    barrier = threading.Barrier(2)

    def _transition(_index: int) -> tuple[str, str | None]:
        barrier.wait(timeout=10)
        try:
            sesv2.put_dedicated_ip_pool_scaling_attributes(
                PoolName=pool_name, ScalingMode="MANAGED"
            )
            return ("ok", None)
        except ClientError as err:
            return ("error", err.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(_transition, range(2)))

    outcomes = [r[0] for r in results]
    errors = [r[1] for r in results if r[0] == "error"]
    # AWS may serialize both identical writes or reject the loser; both outcomes are valid.
    for code in errors:
        assert code == "ConcurrentModificationException", (
            f"loser raised {code}, not ConcurrentModificationException (results={results})"
        )
    assert outcomes.count("ok") >= 1, f"expected at least one winner, got {results}"

    after = sesv2.get_dedicated_ip_pool(PoolName=pool_name)["DedicatedIpPool"]
    assert after["ScalingMode"] == "MANAGED", (
        f"expected pool to converge to MANAGED after the race, got {after['ScalingMode']} "
        f"(results={results})"
    )


def _retry_delete_pool(sesv2, pool_name: str, attempts: int = 5, delay_s: float = 2.0) -> None:
    for i in range(attempts):
        try:
            sesv2.delete_dedicated_ip_pool(PoolName=pool_name)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConcurrentModificationException" or i == attempts - 1:
                raise
            time.sleep(delay_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
