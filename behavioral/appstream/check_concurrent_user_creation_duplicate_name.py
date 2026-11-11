"""concurrent-user-creation-duplicate-name."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-user-creation-duplicate-name"
GROUP = "concurrency"
SERVICES = ["appstream"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateUser calls on one UserName+AuthenticationType all succeed, because
    CreateUser is idempotent for an identical identity, and exactly one enabled user exists for
    that UserName afterwards."""
    appstream = ctx.client("appstream")
    user_name = f"{ctx.unique_name('sim2real-appstream-race-user-')}@example.com"
    auth_type = "USERPOOL"
    ctx.on_cleanup(lambda: appstream.delete_user(UserName=user_name, AuthenticationType=auth_type))

    racers = 6

    def _try_create(_i: int):
        try:
            appstream.create_user(UserName=user_name, AuthenticationType=auth_type, MessageAction="SUPPRESS")
            return ("ok", None)
        except Exception as err:  # noqa: BLE001
            from botocore.exceptions import ClientError

            if isinstance(err, ClientError):
                return ("error", err.response["Error"]["Code"])
            raise

    with ThreadPoolExecutor(max_workers=racers) as pool:
        futures = [pool.submit(_try_create, i) for i in range(racers)]
        results = [f.result() for f in as_completed(futures)]

    successes = [r for r in results if r[0] == "ok"]

    # CreateUser is idempotent for this identity: every racer succeeds outright.
    assert len(successes) == racers, f"expected all {racers} racers to succeed, got: {results}"

    # the identity is never double-allocated: exactly one user exists for this name, enabled
    # (allow for eventual consistency between CreateUser and DescribeUsers)
    left = ctx.time_left()
    deadline = time.monotonic() + (30 if left is None else min(30, left))
    matches: list = []
    while time.monotonic() < deadline:
        described = appstream.describe_users(AuthenticationType=auth_type)["Users"]
        matches = [u for u in described if u["UserName"] == user_name]
        if len(matches) == 1:
            break
        time.sleep(2)
    assert len(matches) == 1, f"expected exactly 1 user for {user_name}, got: {matches}"
    assert matches[0]["Enabled"] is True, f"expected Enabled=True, got: {matches[0]}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
