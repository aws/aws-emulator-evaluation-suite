"""concurrent-modify-route-server-optimistic-lock-conflict."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "concurrent-modify-route-server-optimistic-lock-conflict"
GROUP = "concurrency"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two simultaneous ModifyRouteServer calls with opposite SnsNotificationsEnabled leave the route server
    available with one value on three spaced reads, matching a submitted value; at least one call succeeds and
    a rejected one answers IncorrectState.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-rsmod-")

    rs_id = ec2.create_route_server(
        AmazonSideAsn=4200000101,
        TagSpecifications=_tag_spec("route-server", name),
    )["RouteServer"]["RouteServerId"]
    ctx.on_cleanup(lambda: ec2.delete_route_server(RouteServerId=rs_id))

    _poll_until(lambda: _rs_state(ec2, rs_id), lambda s: s == "available", timeout_s=120, interval_s=3)

    barrier = threading.Barrier(2)

    def _call(sns_enabled: bool):
        barrier.wait(timeout=30)
        try:
            resp = ec2.modify_route_server(RouteServerId=rs_id, SnsNotificationsEnabled=sns_enabled)
            return ("ok", resp["RouteServer"]["SnsNotificationsEnabled"])
        except Exception as exc:
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return ("error", exc.response["Error"]["Code"])
            raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_call, True)
        fut_b = pool.submit(_call, False)
        result_a = fut_a.result()
        result_b = fut_b.result()

    results = [result_a, result_b]
    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    # Both racing calls usually succeed (a fast metadata update, not a long-running state
    # transition); a rejection must be the busy-resource code IncorrectState, never a server error.
    assert len(successes) >= 1, f"expected at least one ModifyRouteServer to succeed, got {results}"
    for _, code in failures:
        assert code == "IncorrectState", (
            f"expected a rejected concurrent ModifyRouteServer to fail with IncorrectState, got {code}"
        )

    final_state = _poll_until(
        lambda: _rs_state(ec2, rs_id), lambda s: s == "available", timeout_s=120, interval_s=3
    )
    assert final_state == "available"

    # When both calls succeed, every boolean is a submitted value, so membership alone cannot fail; a
    # corrupted merge would show as the value flapping, so three spaced reads must agree.
    settled_values = []
    for i in range(3):
        settled_values.append(_rs_sns_enabled(ec2, rs_id))
        if i < 2:
            time.sleep(2)
    assert len(set(settled_values)) == 1, (
        f"SnsNotificationsEnabled flapped across independent reads ({settled_values}) -- "
        f"indicates an ambiguous convergence, not a settled value"
    )
    settled_value = settled_values[0]
    submitted_values = {v for _, v in successes}
    assert settled_value in submitted_values, (
        f"final SnsNotificationsEnabled ({settled_value!r}) does not match either "
        f"racing call's submitted value ({submitted_values!r}) -- indicates a corrupted convergence"
    )


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _rs_state(ec2, rs_id: str):
    return ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0]["State"]


def _rs_sns_enabled(ec2, rs_id: str):
    return ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"][0]["SnsNotificationsEnabled"]


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
