"""concurrent-admin-set-user-password-leaves-exactly-one-usable-password."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-admin-set-user-password-leaves-exactly-one-usable-password"
GROUP = 'concurrency'
SERVICES = ['cognito-idp']

_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_N = 5


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After five concurrent AdminSetUserPassword calls with distinct permanent passwords, exactly
    one password authenticates and returns an AccessToken; the other four are refused with
    NotAuthorizedException and the exact message."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=dict(_POOL_TAGS),
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _p=pool_id: c.delete_user_pool(UserPoolId=_p))

    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )

    passwords = [f"Sim2Real-Race-{i}-Passw0rd!" for i in range(_N)]

    def _setter(pw):
        def _do():
            return c.admin_set_user_password(
                UserPoolId=pool_id, Username=username, Password=pw, Permanent=True
            )
        return _do

    write_results = _run_concurrent([_setter(pw) for pw in passwords], timeout_s=120)
    write_errors = _concurrent_error_codes(write_results)
    assert not write_errors, (
        f"AdminSetUserPassword is last-write-wins and every racer should be accepted; "
        f"these were refused: {write_errors!r}"
    )

    # Which password won is not asserted -- only that exactly one did. That is the invariant
    # AWS guarantees under contention; naming a winner would be a claim about scheduling.
    successes, failures = [], {}
    for pw in passwords:
        outcome = _authenticate(c, pool_id, client_id, username, pw)
        if isinstance(outcome, tuple):
            failures[pw] = outcome
        else:
            successes.append(outcome)

    assert len(successes) == 1, (
        f"exactly one of the {_N} concurrently written passwords must authenticate, got "
        f"{len(successes)}; refusals were {failures!r}"
    )
    assert {code for code, _ in failures.values()} == {"NotAuthorizedException"}, (
        f"a superseded password was refused with the wrong code: {failures!r}"
    )
    messages = {message for _, message in failures.values()}
    assert messages == {"Incorrect username or password."}, (
        f"a superseded password was refused with the wrong message: {failures!r}"
    )
    assert successes[0]["AuthenticationResult"]["AccessToken"], (
        f"the surviving password issued no token: {successes[0]!r}"
    )

    user = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert user["UserStatus"] == "CONFIRMED" and user["Enabled"] is True, (
        f"the concurrent writes damaged the user: UserStatus={user['UserStatus']!r} "
        f"Enabled={user['Enabled']!r}"
    )


def _authenticate(c, pool_id, client_id, username, password):
    """Return the AdminInitiateAuth response, or the (code, message) of the refusal.

    Account-level auth-attempt throttling would otherwise turn a legitimate refusal into
    TooManyRequestsException, so that one code -- and only that one -- is retried; a
    NotAuthorizedException is taken at face value on the first attempt.
    """
    for _ in range(3):
        try:
            return c.admin_initiate_auth(
                UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
                AuthParameters={"USERNAME": username, "PASSWORD": password},
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TooManyRequestsException":
                time.sleep(5.0)
                continue
            return code, e.response["Error"].get("Message")
    raise AssertionError(
        f"auth for one of the racing passwords stayed throttled across 3 attempts, so the "
        f"exactly-one invariant could not be measured for user {username!r}"
    )


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:  # noqa: BLE001 - the exception IS the result under contention
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


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
