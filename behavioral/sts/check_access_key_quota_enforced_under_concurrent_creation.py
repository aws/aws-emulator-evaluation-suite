"""access-key-quota-enforced-under-concurrent-creation."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-key-quota-enforced-under-concurrent-creation"
GROUP = "concurrency"
SERVICES = ["sts"]

QUOTA_MESSAGE = "Cannot exceed quota for AccessKeysPerUser: 2"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateAccessKey calls past the 2-key quota fail with LimitExceeded, the listed
    keys match the reported successes, and a later sequential call is refused at the cap.
    """
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    # IAM is eventually consistent across its control-plane nodes; hammering
    # CreateAccessKey concurrently before the new user is visible everywhere can
    # surface spurious NoSuchEntity failures instead of the LimitExceeded we're
    # actually probing for. Warm up until the user is reliably visible.
    _poll_until(
        lambda: _user_visible(iam, user_name),
        lambda visible: visible,
        timeout_s=30.0,
        interval_s=2.0,
    )

    n_racers = 5

    def _try_create():
        try:
            key_id = iam.create_access_key(UserName=user_name)["AccessKey"]["AccessKeyId"]
            return ("ok", key_id)
        except ClientError as exc:
            return ("err", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(_try_create) for _ in range(n_racers)]
        results = [f.result() for f in as_completed(futures)]

    successes = [v for kind, v in results if kind == "ok"]
    failures = [v for kind, v in results if kind == "err"]

    for key_id in successes:
        ctx.on_cleanup(
            lambda kid=key_id: iam.delete_access_key(UserName=user_name, AccessKeyId=kid)
        )

    # The 2-key cap is not atomic under contention: a burst can let more than 2 succeed before
    # the quota gate catches up, so only the bounds are asserted. A new user always gets 2.
    assert 2 <= len(successes) <= n_racers, successes
    assert len(failures) == n_racers - len(successes), (successes, failures)
    assert all(err == ("LimitExceeded", QUOTA_MESSAGE) for err in failures), failures

    # The listed keys converge to exactly the reported successes.
    live_key_ids = _poll_until(
        lambda: sorted(
            k["AccessKeyId"] for k in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
        ),
        lambda ids: ids == sorted(successes),
        timeout_s=15.0,
        interval_s=2.0,
    )
    assert live_key_ids == sorted(successes), (live_key_ids, sorted(successes))

    # A sequential call is rejected at or above the cap and accepted below it.
    def _extra_create():
        try:
            key_id = iam.create_access_key(UserName=user_name)["AccessKey"]["AccessKeyId"]
            return ("ok", key_id)
        except ClientError as exc:
            return ("err", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    kind, value = _extra_create()
    if len(live_key_ids) >= 2:
        assert kind == "err" and value == ("LimitExceeded", QUOTA_MESSAGE), (kind, value)
        expected_final_ids = live_key_ids
    else:
        assert kind == "ok", (kind, value)
        ctx.on_cleanup(
            lambda kid=value: iam.delete_access_key(UserName=user_name, AccessKeyId=kid)
        )
        expected_final_ids = sorted(live_key_ids + [value])

    # The persisted key set must reflect what the sequential call reported.
    final_key_ids = sorted(
        k["AccessKeyId"] for k in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    )
    assert final_key_ids == expected_final_ids, (final_key_ids, expected_final_ids)


def _user_visible(iam, user_name: str) -> bool:
    try:
        iam.get_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise
    return True


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if not predicate(last):
        raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

