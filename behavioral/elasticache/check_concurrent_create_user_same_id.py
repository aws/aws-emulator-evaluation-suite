"""concurrent-create-user-same-id."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

def _describe_one(fn, list_key, id_field, id_value, **extra):
    """describe wrapper: return the single item, None on NotFound / empty list."""
    try:
        resp = fn(**{id_field: id_value}, **extra)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code") or ""
        if "NotFound" in code:
            return None
        raise
    items = resp.get(list_key, [])
    return items[0] if items else None

def _poll(probe, predicate, timeout_s=600, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)

def _wait_status(fn, list_key, id_field, id_value, status_field, target, timeout_s=1800, interval_s=15, **extra):
    return _poll(
        lambda: _describe_one(fn, list_key, id_field, id_value, **extra),
        lambda item: item is not None and item.get(status_field) == target,
        timeout_s, interval_s,
    )

def _run_calls(fn, n):
    """Invoke fn() n times concurrently; return [(ok, value_or_(code, message))]."""
    import concurrent.futures
    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(fn) for _ in range(n)]
        for f in concurrent.futures.as_completed(futures):
            try:
                out.append((True, f.result()))
            except ClientError as e:
                error = e.response.get("Error", {})
                out.append((False, (error.get("Code"), error.get("Message"))))
            except Exception as e:
                out.append((False, repr(e)))
    return out

def _wait_user_status(ec, user_id, status, timeout_s=300, interval_s=5):
    return _wait_status(ec.describe_users, "Users", "UserId", user_id, "Status", status, timeout_s, interval_s)

CHECK = "concurrent-create-user-same-id"
GROUP = 'concurrency'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing CreateUser calls with the same UserId: exactly one succeeds, the rest get UserAlreadyExists."""
    ec = ctx.client("elasticache")
    user_id = ctx.unique_name("sim2real-behav-ecu-race-")
    ctx.on_cleanup(lambda: ec.delete_user(UserId=user_id))

    def attempt():
        return ec.create_user(
            UserId=user_id,
            UserName=user_id,
            Engine="redis",
            AccessString="on ~* +@all",
            NoPasswordRequired=True,
        )

    results = _run_calls(attempt, 5)
    successes = [value for ok, value in results if ok]
    failures = [value for ok, value in results if not ok]
    assert len(successes) == 1, f"expected exactly 1 success, got {len(successes)}: {results}"
    assert len(failures) == 4, failures
    expected_message = f"User {user_id} already exists."
    for failure in failures:
        assert failure == ("UserAlreadyExists", expected_message), failures

    user = _wait_user_status(ec, user_id, "active")
    assert user is not None, f"expected user {user_id} to reach active status, got no record"
    assert user["UserId"] == user_id, f"expected UserId {user_id}, got {user.get('UserId')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
