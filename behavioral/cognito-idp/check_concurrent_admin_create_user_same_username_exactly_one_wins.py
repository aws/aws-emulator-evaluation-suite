"""concurrent-admin-create-user-same-username-exactly-one-wins."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-admin-create-user-same-username-exactly-one-wins"
GROUP = 'user-lifecycle'
SERVICES = ['cognito-idp']

_LENIENT_PASSWORD_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of several concurrent AdminCreateUser calls for the same Username exactly one succeeds and
    every other one answers UsernameExistsException "User account already exists"; AdminGetUser then
    returns the user."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c)
    username = ctx.unique_name("sim2real-behav-cip-race-user-")
    n = 8

    def attempt():
        return c.admin_create_user(
            UserPoolId=pool_id,
            Username=username,
            MessageAction="SUPPRESS",
            UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
        )

    results = _run_concurrent([attempt for _ in range(n)], timeout_s=90)
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))

    successes = _concurrent_successes(results)
    assert successes == 1, f"expected exactly 1 of {n} racing creates to win, got {successes}"

    error_codes = _concurrent_error_codes(results)
    assert len(error_codes) == n - 1, (
        f"expected {n - 1} failures, got {len(error_codes)}: {error_codes}"
    )
    assert all(x == "UsernameExistsException" for x in error_codes), (
        f"expected every losing racer to get UsernameExistsException, got {error_codes}"
    )
    messages = [r.response.get("Error", {}).get("Message") for r in results if isinstance(r, ClientError)]
    assert messages == ["User account already exists"] * (n - 1), messages

    got = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert got["Username"] == username, (
        f"expected the winning username {username!r} to be independently readable via "
        f"admin_get_user, got {got['Username']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
