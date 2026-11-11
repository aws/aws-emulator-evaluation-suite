"""login-profile-create-race-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "login-profile-create-race-single-winner"
GROUP = "state-machine"
SERVICES = ["iam"]

_RACERS = 8
_PASSWORD = "Sim2Real!Aa9$Xk42Qz#"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateLoginProfile calls for the same user race to exactly one winner."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-loginrace-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    ctx.on_cleanup(lambda: _safe_delete_login_profile(iam, user_name))

    def attempt(_i):
        try:
            iam.create_login_profile(UserName=user_name, Password=_PASSWORD)
            return "ok"
        except Exception as exc:
            return _client_error_code(exc)

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        results = list(pool.map(attempt, range(_RACERS)))

    wins = results.count("ok")
    losses = results.count("EntityAlreadyExists")
    assert wins == 1, f"expected exactly 1 winner, got {wins} (results={results})"
    assert losses == _RACERS - 1, (
        f"expected {_RACERS - 1} losers rejected with EntityAlreadyExists, got {losses} "
        f"(results={results})"
    )

    # the profile itself must be in a consistent, single, active state after the race
    got = iam.get_login_profile(UserName=user_name)["LoginProfile"]
    assert got["UserName"] == user_name, f"expected login profile for {user_name}, got {got}"
    assert got.get("PasswordResetRequired", False) is False, (
        f"CreateLoginProfile was not given PasswordResetRequired, expected it to default to "
        f"False, got {got.get('PasswordResetRequired')}"
    )


def _safe_delete_login_profile(iam, user_name):
    try:
        iam.delete_login_profile(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _client_error_code(exc):
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    raise exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
