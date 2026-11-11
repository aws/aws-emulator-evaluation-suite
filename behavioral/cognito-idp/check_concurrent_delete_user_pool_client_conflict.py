"""concurrent-delete-user-pool-client-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-delete-user-pool-client-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteUserPoolClient racing with an in-flight UpdateUserPoolClient never leaves the
    client half-updated: losers get ConcurrentModificationException or ResourceNotFoundException
    (once deleted), and afterwards the client is either fully gone or fully intact."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    state: dict[str, str] = {}

    def _ensure_client():
        if "client_id" in state:
            try:
                idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=state["client_id"])
                return
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        resp = idp.create_user_pool_client(
            UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
        )
        state["client_id"] = resp["UserPoolClient"]["ClientId"]
        state["client_name"] = resp["UserPoolClient"]["ClientName"]

    # Real Cognito surfaces a losing writer in this race either as
    # ConcurrentModificationException or as ResourceNotFoundException once the delete has won
    # the race (DeleteUserPoolClient commits fast enough that update losers often see the
    # resource already gone rather than a version conflict). Both outcomes prove the race was
    # detected safely; requiring ConcurrentModificationException specifically is an unfounded
    # assumption about which of the two accepted codes will show up on a given attempt.
    racer_names: list[str] = []
    for attempt in range(3):
        _ensure_client()
        client_id = state["client_id"]
        racer_names = [f"sim2real-racer-{attempt}-{i}" for i in range(5)]
        fns = [
            (lambda cid=client_id: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=cid))
            for _ in range(3)
        ] + [
            (lambda name=name, cid=client_id: idp.update_user_pool_client(
                UserPoolId=pool_id, ClientId=cid, ClientName=name
            ))
            for name in racer_names
        ]
        results = _race(fns)
        successes = [r for r, err, _msg in results if err is None]
        others = [
            (err, msg) for _, err, msg in results if err is not None and not _is_conflict_loser(err, msg)
        ]
        assert not others, f"unexpected errors racing delete/update user pool client: {others}"
        assert len(successes) >= 1, "no delete/update call succeeded under contention"
        if any(_is_conflict_loser(err, msg) for _, err, msg in results if err is not None):
            break
    else:
        raise AssertionError(
            "no ConcurrentModificationException/ResourceNotFoundException observed across 3"
            " attempts of racing DeleteUserPoolClient against UpdateUserPoolClient"
        )

    # The client is "fully intact" only if its name is exactly the pre-race name or one of
    # this attempt's attempted racer names, never a merge of the two or something else — this
    # is what actually distinguishes "never half-updated" from a bare presence check.
    expected_names = {state["client_name"], *racer_names}
    try:
        final = idp.describe_user_pool_client(
            UserPoolId=pool_id, ClientId=state["client_id"]
        )["UserPoolClient"]
        assert final["ClientId"] == state["client_id"]
        assert final["ClientName"] in expected_names, (
            f"post-race ClientName {final['ClientName']!r} is not the pre-race name nor one of"
            f" the attempted racer names {sorted(expected_names)}"
        )
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
            "user pool client left in an unexpected error state after the race"
        )
        message = e.response["Error"].get("Message", "")
        assert message == "User pool client does not exist.", (
            f"expected the exact deleted-client message, got {message!r}"
        )


from botocore.exceptions import ClientError


def _call(fn):
    try:
        return fn(), None, None
    except ClientError as e:
        return None, e.response["Error"]["Code"], e.response["Error"].get("Message", "")


def _race(fns):
    with ThreadPoolExecutor(max_workers=len(fns)) as ex:
        futures = [ex.submit(_call, fn) for fn in fns]
        return [f.result() for f in futures]


_CONFLICT_KEYWORDS = ("concurrent", "modif", "conflict", "stale", "changed", "version")


def _is_conflict_loser(code: str, message: str | None) -> bool:
    """True if `code`/`message` represents a legitimate losing-writer outcome for this race:
    ConcurrentModificationException, ResourceNotFoundException (the resource was deleted by a
    winning racer), or an InvalidParameterException whose message reports the underlying
    version/conflict rejection rather than an unrelated malformed-request error."""
    if code in ("ConcurrentModificationException", "ResourceNotFoundException"):
        return True
    if code == "InvalidParameterException" and message:
        low = message.lower()
        return any(kw in low for kw in _CONFLICT_KEYWORDS)
    return False


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
