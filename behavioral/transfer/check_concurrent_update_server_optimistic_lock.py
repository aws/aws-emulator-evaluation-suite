"""concurrent-update-server-optimistic-lock."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-server-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateServer calls on one server both succeed, as UpdateServer takes no lock token, and the stored
    banner equals one of the two written values, never a blend."""
    transfer = ctx.client("transfer")
    server_id = transfer.create_server(Tags=[{"Key": "sim2real", "Value": CHECK}])["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    value_a = "sim2real-race-banner-a"
    value_b = "sim2real-race-banner-b"

    def update(value: str):
        transfer.update_server(ServerId=server_id, PreAuthenticationLoginBanner=value)

    results = _race(lambda: update(value_a), lambda: update(value_b))

    failures = [r for r in results if not r[0]]
    assert not failures, f"expected both concurrent UpdateServer calls to succeed (no lock token exists), got failures: {failures}"

    # The persisted banner must equal exactly one of the two racing values -- proving the
    # server serializes the two writes rather than corrupting/merging them.
    described = transfer.describe_server(ServerId=server_id)["Server"]
    final_banner = described.get("PreAuthenticationLoginBanner")
    assert final_banner in (value_a, value_b), f"banner {final_banner!r} matches neither racing write -- data corruption"


def _race(fn_a, fn_b):
    """Fire fn_a and fn_b truly concurrently via a barrier; return [(ok, value_or_code), ...]
    in submission order (fn_a first, fn_b second)."""
    barrier = threading.Barrier(2)

    def _wrapped(fn):
        barrier.wait(timeout=10)
        try:
            fn()
            return (True, None)
        except ClientError as exc:
            return (False, exc.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_wrapped, fn_a), pool.submit(_wrapped, fn_b)]
        return [f.result(timeout=30) for f in futures]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
