"""put-account-properties."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-account-properties"
GROUP = "account_summary"
SERVICES = ["iam"]


def _error_code(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _with_authorization_details(base, message):
    """IAM's access-denied text: ``base`` plus a per-request authorization id, the only part read
    back from ``message``. The console link names us-east-1, where IAM's global endpoint signs."""
    region = "us-east-1"
    marker = "authorization id: "
    auth_id = message.rsplit(marker, 1)[-1] if message and marker in message else "<absent>"
    return (
        f"{base}. Go to https://{region}.console.aws.amazon.com/iam/home?region={region}"
        f"#/authorization-details/{auth_id} for complete details, or call the "
        f"GetRequestAuthorizationDetails API with the following authorization id: {auth_id}"
    )


def _unprivileged_client(ctx):
    """Return ``(iam client, user_arn)`` for a new zero-permission user with a fresh access key.
    Polls STS until the key authenticates (new keys propagate eventually); cleanup is registered."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("nopriv-")
    user_arn = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])[
        "User"
    ]["Arn"]

    def _cleanup():
        try:
            for k in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=user_name, AccessKeyId=k["AccessKeyId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_user(UserName=user_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    created = iam.create_access_key(UserName=user_name)["AccessKey"]
    creds = {
        "aws_access_key_id": created["AccessKeyId"],
        "aws_secret_access_key": created["SecretAccessKey"],
    }
    unpriv_sts = ctx.client("sts", creds=creds)
    # Bounded by the runner's remaining time, so a key that never authenticates fails here.
    budget_s = max(1.0, min(60.0, (ctx.time_left() or 60.0) - 5.0))
    deadline = time.monotonic() + budget_s
    while True:
        try:
            unpriv_sts.get_caller_identity()
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidClientTokenId", "InvalidAccessKeyId"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"minted access key not recognized within {budget_s:.0f}s; last {code!r}")
            time.sleep(3)
    return ctx.client("iam", creds=creds), user_arn


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:iam-account-properties",
)
def run(ctx) -> None:
    """PutAccountProperties flips RoleManager/Enabled as GetAccountProperties shows; a key without
    the Namespace/Name '/' fails InvalidInput and a zero-permission user fails AccessDenied, each
    with AWS's exact message and no change. The original value is then restored."""
    iam = ctx.client("iam")
    if not hasattr(iam, "get_account_properties"):
        raise AssertionError("get_account_properties not in public IAM API")
    original = iam.get_account_properties().get("Properties", {})
    original_value = original.get("RoleManager/Enabled", "false")

    ctx.on_cleanup(
        lambda: iam.put_account_properties(
            Properties={"RoleManager/Enabled": original_value}
        )
    )

    new_value = "false" if original_value == "true" else "true"
    iam.put_account_properties(Properties={"RoleManager/Enabled": new_value})
    refreshed = iam.get_account_properties()["Properties"]
    assert refreshed.get("RoleManager/Enabled") == new_value, (
        f"expected RoleManager/Enabled={new_value!r}, got {refreshed}"
    )

    # The key still matches the modeled ^[A-Za-z][A-Za-z0-9/_-]*$ pattern, so the rejection is
    # business logic (InvalidInput), not the ValidationError a pattern violation raises.
    code, message = _error_code(
        lambda: iam.put_account_properties(Properties={"NoSlashHere": "true"})
    )
    assert code == "InvalidInput", (
        f"expected InvalidInput for a malformed property key, got {code}"
    )
    expected = "Property key must be in format Namespace/PropertyName: NoSlashHere"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    after_bad_key = iam.get_account_properties()["Properties"]
    assert "NoSlashHere" not in after_bad_key, (
        f"rejected write leaked into account properties: {after_bad_key}"
    )
    assert after_bad_key.get("RoleManager/Enabled") == new_value, (
        f"rejected malformed-key write disturbed RoleManager/Enabled: {after_bad_key}"
    )

    unpriv, unpriv_arn = _unprivileged_client(ctx)
    code2, message2 = _error_code(
        lambda: unpriv.put_account_properties(
            Properties={"RoleManager/Enabled": "true"}
        )
    )
    assert code2 == "AccessDenied", (
        f"expected AccessDenied for a zero-permission caller, got {code2}"
    )
    expected2 = _with_authorization_details(
        f"User: {unpriv_arn} is not authorized to perform: iam:PutAccountProperties on resource: "
        f"* because no identity-based policy allows the iam:PutAccountProperties action",
        message2,
    )
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"
    after_denied = iam.get_account_properties()["Properties"]
    assert after_denied.get("RoleManager/Enabled") == new_value, (
        f"denied write from a zero-permission caller changed RoleManager/Enabled: {after_denied}"
    )

    iam.put_account_properties(Properties={"RoleManager/Enabled": original_value})
    restored = iam.get_account_properties()["Properties"]
    assert restored.get("RoleManager/Enabled") == original_value, (
        f"expected restore to RoleManager/Enabled={original_value!r}, got {restored}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
