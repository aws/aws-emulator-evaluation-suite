"""put-console-authorization-configuration-double-put-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-console-authorization-configuration-double-put-conflict-rejected"
GROUP = "console-authorization"
SERVICES = ["signin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:signin-console-authorization")
def run(ctx) -> None:
    """A second PutConsoleAuthorizationConfiguration on an enabled target is rejected with ConflictException
    "Configuration already exists" and leaves it enabled; after Delete the identical Put succeeds, so the
    conflict tracks the enabled state.
    """
    signin = _east_client(ctx)
    account_id = _account_id(ctx)
    ctx.on_cleanup(lambda: _safe_delete(signin, account_id))

    first = signin.put_console_authorization_configuration(targetId=account_id)
    assert first["consoleAuthorizationEnabled"] is True, f"expected first Put to enable, got {first!r}"

    code = _error_code(lambda: signin.put_console_authorization_configuration(targetId=account_id))
    assert code == ("ConflictException", "Configuration already exists"), (
        f"expected ConflictException re-Putting an already-enabled target, got {code!r}"
    )

    # still enabled -- the rejected re-Put didn't corrupt/disable the existing configuration
    get_resp = signin.get_console_authorization_configuration(targetId=account_id)
    assert get_resp["consoleAuthorizationEnabled"] is True, (
        f"expected still enabled after the rejected re-Put, got {get_resp!r}"
    )

    # restore: the conflict is tied to the already-enabled STATE, not the targetId -- Delete
    # clears that state, and an otherwise-identical Put against the same target now succeeds.
    delete_resp = signin.delete_console_authorization_configuration(targetId=account_id)
    assert delete_resp["consoleAuthorizationEnabled"] is False, (
        f"expected Delete to report disabled, got {delete_resp!r}"
    )

    restored = signin.put_console_authorization_configuration(targetId=account_id)
    assert restored["consoleAuthorizationEnabled"] is True, (
        f"expected Put to succeed again after Delete cleared the conflicting state, got {restored!r}"
    )


def _east_client(ctx):
    """Console-authorization writes are accepted only in us-east-1, so every target is called there."""
    return ctx.client("signin", region="us-east-1")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _safe_delete(signin, account_id: str) -> None:
    try:
        signin.delete_console_authorization_configuration(targetId=account_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    """The (Code, Message) of the ClientError fn() raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
