"""account-name-concurrent-writes-atomic."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "account-name-concurrent-writes-atomic"
GROUP = "concurrency"
SERVICES = ["account"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:account-name")
def run(ctx) -> None:
    """N concurrent PutAccountName calls each write a whole, distinct name, and the account settles
    on exactly one of those candidates, never an interleaved partial value, so the overwrite is
    atomic under contention."""
    account = ctx.client("account")

    original_name = account.get_account_information()["AccountName"]
    ctx.on_cleanup(lambda: account.put_account_name(AccountName=original_name))

    candidates = [ctx.unique_name(f"sim2real-behav-race{i}-") for i in range(6)]

    def _put(name: str) -> None:
        account.put_account_name(AccountName=name)

    with ThreadPoolExecutor(max_workers=len(candidates)) as pool:
        futures = [pool.submit(_put, name) for name in candidates]
        for fut in as_completed(futures):
            fut.result()  # surface any exception; every racer must succeed

    deadline = time.time() + 60
    final_name = None
    while time.time() < deadline:
        final_name = account.get_account_information()["AccountName"]
        if final_name in candidates:
            break
        time.sleep(3)
    assert final_name in candidates, (
        f"final account name {final_name!r} did not converge to one of the racing writers' "
        f"values {candidates!r} within 60s -- indicates a corrupted/interleaved write"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
