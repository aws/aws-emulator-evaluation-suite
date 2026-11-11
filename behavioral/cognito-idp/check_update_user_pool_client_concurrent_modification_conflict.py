"""update-user-pool-client-concurrent-modification-conflict."""
from __future__ import annotations

import threading

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-pool-client-concurrent-modification-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]

# AWS's message nests its own template; this is the literal string it returns.
CONFLICT_MESSAGE = (
    "Only one request to update this Only one request to mutate a user pool client can be "
    "processed at a time. can be processed at a time."
)
NOT_FOUND_MESSAGE = "User pool client does not exist."


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """Racing updates, then an update/delete pair, on one app client: each race has a winner,
    losers get only ConcurrentModificationException or ResourceNotFoundException with exact
    messages, and the client ends as a successful update's name, or gone when a delete won."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_client(ctx, pool_id)

    n = 10
    names = {i: f"sim2real-race-{i}" for i in range(n)}
    calls = [
        (lambda i=i: idp.update_user_pool_client(
            UserPoolId=pool_id, ClientId=client_id, ClientName=names[i],
        ))
        for i in range(n)
    ]
    results = _race(calls)
    for _, code, message in results:
        if code is None:
            continue
        assert code == "ConcurrentModificationException", f"unexpected error code: {code}"
        assert message == CONFLICT_MESSAGE, (
            f"expected the exact {code} message {CONFLICT_MESSAGE!r}, got {message!r}"
        )
    winning_names = {names[i] for i, r in enumerate(results) if r[0]}
    assert winning_names, "expected at least one UpdateUserPoolClient racer to win"

    final = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert final["ClientName"] in winning_names, (
        f"post-race ClientName {final['ClientName']!r} is not among the winning writes {winning_names}"
    )

    pair_final_name = "sim2real-race-pair-final"
    pair_results = _race([
        lambda: idp.update_user_pool_client(
            UserPoolId=pool_id, ClientId=client_id, ClientName=pair_final_name,
        ),
        lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id),
    ])
    update_won, delete_won = pair_results[0][0], pair_results[1][0]
    assert update_won or delete_won, "expected one side of the update/delete race to win"
    expected_by_code = {
        "ConcurrentModificationException": CONFLICT_MESSAGE,
        "ResourceNotFoundException": NOT_FOUND_MESSAGE,
    }
    for _, code, message in pair_results:
        if code is None:
            continue
        assert code in expected_by_code, f"unexpected error code on losing side: {code}"
        assert message == expected_by_code[code], (
            f"expected the exact {code} message {expected_by_code[code]!r}, got {message!r}"
        )

    if delete_won:
        try:
            idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
            raise AssertionError("DeleteUserPoolClient succeeded but the client is still readable")
        except ClientError as e:
            assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
                f"unexpected error reading the deleted client: {e.response['Error']['Code']}"
            )
            assert e.response["Error"].get("Message") == NOT_FOUND_MESSAGE, (
                f"expected the exact deleted-client message {NOT_FOUND_MESSAGE!r}, "
                f"got {e.response['Error'].get('Message')!r}"
            )
    else:
        final_pair = idp.describe_user_pool_client(
            UserPoolId=pool_id, ClientId=client_id
        )["UserPoolClient"]
        assert final_pair["ClientName"] == pair_final_name, (
            f"UpdateUserPoolClient won the race but the client name is "
            f"{final_pair['ClientName']!r}"
        )


def _race(calls):
    n = len(calls)
    barrier = threading.Barrier(n)
    results: list = [None] * n

    def _worker(i, fn):
        barrier.wait()
        try:
            fn()
            results[i] = (True, None, None)
        except ClientError as e:
            error = e.response["Error"]
            results[i] = (False, error["Code"], error.get("Message"))

    threads = [threading.Thread(target=_worker, args=(i, fn)) for i, fn in enumerate(calls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_pool(ctx):
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id):
    idp = ctx.client("cognito-idp")
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: _ignore(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)))
    return client_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
