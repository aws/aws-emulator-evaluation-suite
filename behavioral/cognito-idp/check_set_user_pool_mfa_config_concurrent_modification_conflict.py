"""set-user-pool-mfa-config-concurrent-modification-conflict."""
from __future__ import annotations

import threading

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-user-pool-mfa-config-concurrent-modification-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent SetUserPoolMfaConfig calls setting the same value on one pool all succeed, none with
    ConcurrentModificationException, and the pool then reads MfaConfiguration OFF."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)

    n = 10
    calls = [
        (lambda: idp.set_user_pool_mfa_config(UserPoolId=pool_id, MfaConfiguration="OFF"))
        for _ in range(n)
    ]
    results = _race(calls)
    successes = [r for r in results if r[0]]
    failures = [r for r in results if not r[0]]
    assert len(failures) == 0, (
        f"expected every one of {n} identical racers to succeed (real Cognito performs no "
        f"conflict detection on SetUserPoolMfaConfig), but {len(failures)} were rejected: {failures}"
    )
    assert len(successes) == n, f"expected all {n} racers to succeed, got {len(successes)}"

    final = idp.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert final["MfaConfiguration"] == "OFF", (
        f"expected MfaConfiguration OFF after the race, got {final.get('MfaConfiguration')!r}"
    )


def _race(calls):
    n = len(calls)
    barrier = threading.Barrier(n)
    results: list = [None] * n

    def _worker(i, fn):
        barrier.wait()
        try:
            fn()
            results[i] = (True, None)
        except ClientError as e:
            results[i] = (False, e.response["Error"]["Code"])

    threads = [threading.Thread(target=_worker, args=(i, fn)) for i, fn in enumerate(calls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def _create_pool(ctx):
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
