"""admin-delete-user-and-list-users-race-no-partial-state."""
from __future__ import annotations

import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-delete-user-and-list-users-race-no-partial-state"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListUsers polled during a concurrent AdminDeleteUser sees either a fully populated user
    row or none, never a partial record; the user then leaves ListUsers and AdminGetUser."""
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-race-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    username = ctx.unique_name("sim2real-race-user-")
    password = "Sim2Real-Race-Test1!"
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    snapshots: list[list[dict]] = []
    stop = threading.Event()

    def _poll_loop():
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and not stop.is_set():
            resp = cognito.list_users(
                UserPoolId=pool_id, Filter=f'username = "{username}"'
            )
            snapshots.append(list(resp.get("Users", [])))
            time.sleep(0.05)

    poller = threading.Thread(target=_poll_loop, daemon=True)
    poller.start()
    _wait_for(
        lambda: len(snapshots) >= 1,
        timeout_s=5.0,
        reason="the poller to observe the user present before AdminDeleteUser runs",
    )
    presample_count = len(snapshots)
    cognito.admin_delete_user(UserPoolId=pool_id, Username=username)
    _wait_for(
        lambda: len(snapshots) >= presample_count + 3,
        timeout_s=5.0,
        reason="the poller to collect samples of the aftermath of AdminDeleteUser",
    )
    stop.set()
    poller.join(timeout=5)

    assert snapshots, "no ListUsers samples were collected during the race"

    saw_present = False
    for sample in snapshots:
        assert len(sample) <= 1, f"filter on a single username returned {len(sample)} rows"
        if sample:
            saw_present = True
            user = sample[0]
            for required_key in ("Username", "UserStatus", "Enabled", "UserCreateDate"):
                assert required_key in user, (
                    f"partial user record observed mid-race: missing {required_key!r} in {user!r}"
                )
            assert user["Username"] == username, (
                f"expected sampled row to be for {username!r}, got {user['Username']!r}"
            )
    assert saw_present, "never observed the user present before AdminDeleteUser ran"

    def _absent_now() -> bool:
        resp = cognito.list_users(UserPoolId=pool_id, Filter=f'username = "{username}"')
        return len(resp.get("Users", [])) == 0

    deadline = time.monotonic() + 15.0
    absent = False
    while time.monotonic() < deadline:
        if _absent_now():
            absent = True
            break
        time.sleep(0.5)
    assert absent, "user still visible in ListUsers long after AdminDeleteUser completed"

    code, message = _error(lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=username))
    assert (code, message) == ("UserNotFoundException", "User does not exist."), (
        f"expected UserNotFoundException from AdminGetUser after AdminDeleteUser, got {(code, message)!r}"
    )


def _wait_for(condition, *, timeout_s, reason):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {reason}")


def _error(fn):
    """Call fn(); return its (code, message). A call that succeeds raises: a target that
    accepts what AWS refuses must fail loudly, never as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
