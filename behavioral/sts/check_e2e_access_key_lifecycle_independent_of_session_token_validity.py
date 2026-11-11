"""e2e-access-key-lifecycle-independent-of-session-token-validity."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "e2e-access-key-lifecycle-independent-of-session-token-validity"
GROUP = "state-machine"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """Deleting the IAM access key that minted a GetSessionToken session leaves the session
    credentials usable, and ListAccessKeys no longer lists the deleted key."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-akuser-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    key_id = key["AccessKeyId"]
    key_deleted = {"done": False}

    def _cleanup_key() -> None:
        if not key_deleted["done"]:
            _ignore_no_such_entity(
                lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key_id)
            )

    ctx.on_cleanup(_cleanup_key)

    long_term_creds = {
        "AccessKeyId": key_id,
        "SecretAccessKey": key["SecretAccessKey"],
    }

    # New IAM access keys are eventually consistent; poll until usable.
    long_term_client = _client_with_creds(ctx, "sts", long_term_creds)
    _retry_until_success(
        lambda: long_term_client.get_caller_identity(), timeout_s=30.0, interval_s=2.0
    )

    session_creds = long_term_client.get_session_token(DurationSeconds=900)["Credentials"]
    session_client = _client_with_creds(ctx, "sts", session_creds)

    iam.delete_access_key(UserName=user_name, AccessKeyId=key_id)
    key_deleted["done"] = True

    identity = session_client.get_caller_identity()
    assert identity["Arn"].endswith(f":user/{user_name}"), (
        f"expected session-token credentials minted before key deletion to still "
        f"resolve to user/{user_name}, got {identity['Arn']!r}"
    )

    # Deletion is checked via ListAccessKeys: signature validation with a just-deleted key can
    # keep succeeding for over 240s, longer than the check's time budget allows polling for.
    remaining_key_ids = [
        k["AccessKeyId"] for k in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    ]
    assert key_id not in remaining_key_ids, (
        f"expected deleted key {key_id!r} absent from ListAccessKeys, "
        f"still present in {remaining_key_ids!r}"
    )


def _ignore_no_such_entity(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _client_with_creds(ctx: Any, service: str, creds: dict) -> Any:
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        },
    )


def _retry_until_success(
    fn: Callable[[], Any], *, timeout_s: float, interval_s: float
) -> Any:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

