"""put-account-configuration-concurrent-update-conflicts."""
from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-account-configuration-concurrent-update-conflicts"
GROUP = "concurrency"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:acm-account-configuration")
def run(ctx) -> None:
    """Racing PutAccountConfiguration calls (distinct idempotency tokens) converge to exactly
    one applied DaysBeforeExpiry value; any racer that is rejected gets ConflictException
    specifically, and the account never ends up in a mixed/corrupted state."""
    acm = ctx.client("acm")

    original = acm.get_account_configuration()["ExpiryEvents"]["DaysBeforeExpiry"]

    def _restore() -> None:
        acm.put_account_configuration(
            IdempotencyToken=_token("restore"),
            ExpiryEvents={"DaysBeforeExpiry": original},
        )

    ctx.on_cleanup(_restore)

    n = 8
    # DaysBeforeExpiry must be in [1, 45]. Pick distinct in-range candidates, none equal to
    # the original, so the final value unambiguously identifies which racer's write landed.
    candidates = [d for d in range(1, 46) if d != original][:n]
    barrier = threading.Barrier(n)

    def _racer(days: int) -> tuple[str, int, Any]:
        barrier.wait()
        try:
            acm.put_account_configuration(
                IdempotencyToken=_token(f"r{days}"),
                ExpiryEvents={"DaysBeforeExpiry": days},
            )
            return ("ok", days, None)
        except ClientError as exc:
            messages[days] = exc.response["Error"].get("Message") or ""
            return ("err", days, exc.response["Error"]["Code"])

    messages: dict[int, str] = {}

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(_racer, candidates))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]

    assert len(successes) >= 1, f"expected at least one racer to succeed, got results={results}"

    for _, days, code in failures:
        assert code == "ConflictException", (
            f"racer for DaysBeforeExpiry={days} lost the race with code={code!r}, "
            "expected ConflictException"
        )
        assert messages[days] == (
            "Concurrent requests to PutAccountConfiguration API causing conflicts. Please try again later."
        ), messages[days]

    success_days = [days for _, days, _ in successes]
    final = acm.get_account_configuration()["ExpiryEvents"]["DaysBeforeExpiry"]
    assert final in success_days, (
        f"final DaysBeforeExpiry={final} does not match any racer that actually succeeded "
        f"{success_days} (rejected racers submitted "
        f"{[days for _, days, _ in failures]}); a rejected racer's value landing means "
        "ConflictException did not actually block the write"
    )


def _token(prefix: str) -> str:
    """A PutAccountConfiguration IdempotencyToken must match pattern \\w+ (<=32 chars)."""
    raw = f"{prefix}{uuid.uuid4().hex}"
    return raw[:32]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
