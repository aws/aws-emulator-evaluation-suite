"""concurrent-update-user-pool-client-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-user-pool-client-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


# AWS's message nests its own template; this is the literal string it returns.
CONFLICT_MESSAGE = (
    "Only one request to update this Only one request to mutate a user pool client can be "
    "processed at a time. can be processed at a time."
)


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """Racing UpdateUserPoolClient calls on one app client: at least one succeeds, any loser gets
    only ConcurrentModificationException with its exact message, and the final ClientName is one
    a successful racer wrote."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]

    n_racers = 8
    names = {i: f"sim2real-racer-{i}" for i in range(n_racers)}
    fns = [
        (lambda i=i: idp.update_user_pool_client(
            UserPoolId=pool_id,
            ClientId=client_id,
            ClientName=names[i],
        ))
        for i in range(n_racers)
    ]
    results = _race(fns)
    for _, err, msg in results:
        if err is None:
            continue
        assert err == "ConcurrentModificationException", f"unexpected errors racing UpdateUserPoolClient: {err}"
        assert msg == CONFLICT_MESSAGE, f"expected the exact {err} message {CONFLICT_MESSAGE!r}, got {msg!r}"
    winning_names = {names[i] for i, (_, err, _msg) in enumerate(results) if err is None}
    assert winning_names, "no UpdateUserPoolClient call succeeded under contention"

    final = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert final["ClientName"] in winning_names, (
        f"post-race ClientName {final['ClientName']!r} is not among the winning writes {winning_names}"
    )


from botocore.exceptions import ClientError


def _call(fn):
    try:
        return fn(), None, None
    except ClientError as e:
        return None, e.response["Error"]["Code"], e.response["Error"].get("Message")


def _race(fns):
    with ThreadPoolExecutor(max_workers=len(fns)) as ex:
        futures = [ex.submit(_call, fn) for fn in fns]
        return [f.result() for f in futures]


def _wait_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
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
