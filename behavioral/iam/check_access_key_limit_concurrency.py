"""access-key-limit-concurrency."""
from __future__ import annotations

import concurrent.futures

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-key-limit-concurrency"
GROUP = 'access_keys'
SERVICES = ['iam']

_QUOTA_MESSAGE = "Cannot exceed quota for AccessKeysPerUser: 2"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing CreateAccessKey calls for one user: at least 2 succeed, every loser gets LimitExceeded
    with the exact quota message, ListAccessKeys holds exactly the winners' keys, a later sequential
    call over the cap gets the same error, and calls for the deleted user get the exact NoSuchEntity."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-iam-user-keys-race-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: _delete_user_with_keys(iam, user_name))

    def _create():
        return iam.create_access_key(UserName=user_name)

    results = _run_concurrent([_create for _ in range(5)])

    n_success = _concurrent_successes(results)
    assert n_success >= 2, (
        f"the per-user quota of 2 must at minimum be grantable, got {n_success}"
    )

    # (a) every loser must report the specific quota error.
    error_codes = _concurrent_error_codes(results)
    assert len(error_codes) == len(results) - n_success, (
        f"expected {len(results) - n_success} error code(s) for the losing calls, "
        f"got {len(error_codes)}: {error_codes}"
    )
    assert all(c == "LimitExceeded" for c in error_codes), (
        f"expected all losers to see LimitExceeded, got {error_codes}"
    )
    loser_messages = _concurrent_error_messages(results)
    assert all(m == _QUOTA_MESSAGE for m in loser_messages), (
        f"expected every loser's message to be {_QUOTA_MESSAGE!r}, got {loser_messages}"
    )

    # (b) persisted state must exactly match the calls that reported success.
    succeeded_ids = {
        r["AccessKey"]["AccessKeyId"]
        for r in results
        if not isinstance(r, BaseException)
    }
    listed_ids = {
        k["AccessKeyId"]
        for k in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    }
    assert listed_ids == succeeded_ids, (
        f"persisted keys {sorted(listed_ids)} do not match reported successes "
        f"{sorted(succeeded_ids)}"
    )

    # (c) at/over the cap, a subsequent sequential create must be rejected.
    code, message = _error(lambda: iam.create_access_key(UserName=user_name))
    assert code == "LimitExceeded", (
        f"expected LimitExceeded for a sequential create past the cap, got {code}"
    )
    assert message == _QUOTA_MESSAGE, f"sequential over-cap CreateAccessKey message: {message!r}"

    for key_id in listed_ids:
        iam.delete_access_key(UserName=user_name, AccessKeyId=key_id)
    iam.delete_user(UserName=user_name)

    # the delete above is a free negative assertion: prove the user is gone via an
    # independent read, and that a mutation against the dead user also fails.
    missing_user = f"The user with name {user_name} cannot be found."
    code, message = _error(lambda: iam.get_user(UserName=user_name))
    assert code == "NoSuchEntity", (
        f"expected the deleted user to be gone from an independent read, got {code!r}"
    )
    assert message == missing_user, f"GetUser on the deleted user message: {message!r}"
    code, message = _error(lambda: iam.create_access_key(UserName=user_name))
    assert code == "NoSuchEntity", (
        f"expected a mutation against the deleted user to fail with NoSuchEntity, got {code!r}"
    )
    assert message == missing_user, f"CreateAccessKey on the deleted user message: {message!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _run_concurrent(fns, *, timeout_s: float = 60):
    """Run callables in parallel; return results in submission order. Each entry is
    either the callable's return value or the Exception it raised (captured, NOT
    re-raised), so the check can assert on the DISTRIBUTION of outcomes."""
    results = [None] * len(fns)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                idx = future_to_idx[fut]
                try:
                    results[idx] = fut.result()
                except Exception as exc:  # noqa: BLE001 — captured for the caller to assert on
                    results[idx] = exc
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if not fut.done():
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False)
    return results


def _concurrent_successes(results) -> int:
    return sum(1 for r in results if not isinstance(r, BaseException))


def _concurrent_error_codes(results):
    """Error codes for the entries that raised; non-ClientError exceptions map to
    their class name, successes are skipped."""
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


def _concurrent_error_messages(results):
    """Error messages for the entries that raised a ClientError, in submission order."""
    return [
        r.response.get("Error", {}).get("Message")
        for r in results
        if isinstance(r, ClientError)
    ]


def _delete_user_with_keys(iam, user_name: str) -> None:
    """A user cannot be deleted while it still owns access keys, and a mid-check
    failure can leave any number of them behind."""
    try:
        for k in iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
            try:
                iam.delete_access_key(UserName=user_name, AccessKeyId=k["AccessKeyId"])
            except ClientError as err:
                if err.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
