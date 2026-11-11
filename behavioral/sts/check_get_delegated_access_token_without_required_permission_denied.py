"""get-delegated-access-token-without-required-permission-denied."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-delegated-access-token-without-required-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["sts"]

# GetDelegatedAccessToken validates the TradeInToken's shape before IAM policy evaluation, so a
# Deny cannot be observed via a bogus token. iam:GetUser serves as the twin control because
# GetSessionToken for an IAM user acting on itself is not gated by identity policy either.
_BOGUS_TOKEN = "sim2real-not-a-real-trade-in-token"
_INVALID_TOKEN_MESSAGE = "Invalid trade-in token"
_MANAGED_TAG_KEY = "sim2real:managed"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An explicit Deny on sts:GetDelegatedAccessToken leaves a bogus-token call at ValidationError
    either way (shape validation precedes IAM), while the same Deny on iam:GetUser flips
    AccessDenied to success, proving the policy change was live."""
    iam = ctx.client("iam")

    user_name = ctx.unique_name("sim2real-gdat-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"}])
    ctx.on_cleanup(lambda: _delete_user_if_exists(iam, user_name))

    policy_name = "sim2real-gdat-policy"
    allow_only_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCallerIdentity",
                "Effect": "Allow",
                "Action": "sts:GetCallerIdentity",
                "Resource": "*",
            },
            {
                "Sid": "AllowControlAndTarget",
                "Effect": "Allow",
                "Action": ["iam:GetUser", "sts:GetDelegatedAccessToken"],
                "Resource": "*",
            },
        ],
    }
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": allow_only_policy["Statement"]
        + [
            {
                "Sid": "DenyControlAndTarget",
                "Effect": "Deny",
                "Action": ["iam:GetUser", "sts:GetDelegatedAccessToken"],
                "Resource": "*",
            }
        ],
    }
    iam.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(deny_policy)
    )
    ctx.on_cleanup(lambda: _delete_user_policy_if_exists(iam, user_name, policy_name))

    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: _delete_access_key_if_exists(iam, user_name, access_key["AccessKeyId"])
    )
    creds = {
        "AccessKeyId": access_key["AccessKeyId"],
        "SecretAccessKey": access_key["SecretAccessKey"],
    }
    scoped_sts = _client_with_creds(ctx, "sts", creds)
    scoped_iam = _client_with_creds(ctx, "iam", creds)
    _wait_for_new_credentials(scoped_sts)

    def _attempt_target() -> tuple[str, str | None]:
        """(code, message) of the refusal, or ("SUCCESS", None) when credentials are issued."""
        try:
            scoped_sts.get_delegated_access_token(TradeInToken=_BOGUS_TOKEN)
            return "SUCCESS", None
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    def _attempt_control() -> str | None:
        try:
            scoped_iam.get_user(UserName=user_name)
            return "SUCCESS"
        except ClientError as exc:
            return exc.response["Error"]["Code"]

    # New inline policies lag before enforcement, so poll for the Deny on the control action.
    control_denied = _poll_until(
        _attempt_control,
        lambda c: c == "AccessDenied",
        timeout_s=30.0,
        interval_s=2.0,
        timeout_message="the Deny on iam:GetUser never took effect for this principal",
    )
    # message varies: AWS appends a per-request authorization id to the explicit-deny message.
    assert control_denied == "AccessDenied", f"expected AccessDenied, got {control_denied!r}"

    # Same Deny on the target: ValidationError, not AccessDenied, because shape validation
    # runs ahead of IAM authorization for this operation.
    target_denied = _poll_until(
        _attempt_target,
        lambda r: r[0] is not None,
        timeout_s=30.0,
        interval_s=2.0,
        timeout_message="GetDelegatedAccessToken never returned an error code with the Deny in place",
    )
    assert target_denied == ("ValidationError", _INVALID_TOKEN_MESSAGE), (
        "expected ValidationError (request-shape validation preempts IAM "
        f"auth for this operation) even with an explicit Deny in place, got "
        f"{target_denied!r}"
    )
    assert _attempt_target() == ("ValidationError", _INVALID_TOKEN_MESSAGE)

    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(allow_only_policy),
    )

    # The same policy transition must flip the control to success, proving the update is live.
    control_after = _poll_until(
        _attempt_control,
        lambda c: c != "AccessDenied",
        timeout_s=30.0,
        interval_s=2.0,
        timeout_message="removing the Deny never restored iam:GetUser",
    )
    assert control_after == "SUCCESS", f"expected iam:GetUser to succeed, got {control_after!r}"

    # With the Deny removed the target's outcome is unchanged: it was never policy-gated.
    target_after = _attempt_target()
    assert target_after == ("ValidationError", _INVALID_TOKEN_MESSAGE), (
        "GetDelegatedAccessToken's outcome changed after removing the Deny "
        f"(expected the same ValidationError as before, got {target_after!r}); "
        "if this target actually gates the operation on IAM policy, that is "
        "a genuine fidelity divergence from real AWS's validate-before-"
        "authorize order for this operation"
    )


def _client_with_creds(ctx, service: str, creds: dict[str, Any]):
    # IAM is global and signs as us-east-1 regardless of ctx.region.
    return ctx.client(
        service,
        region="us-east-1" if service == "iam" else None,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        },
    )


def _wait_for_new_credentials(sts_client, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            sts_client.get_caller_identity()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("InvalidClientTokenId", "AccessDenied"):
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"new access key never became active within {timeout_s}s: {last_err}")


def _poll_until(
    probe,
    predicate,
    timeout_s: float = 30.0,
    interval_s: float = 2.0,
    timeout_message: str = "condition was never met",
):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError(f"{timeout_message} (last observed: {result!r})")
    return result


def _delete_user_if_exists(iam, user_name: str) -> None:
    try:
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_user_policy_if_exists(iam, user_name: str, policy_name: str) -> None:
    try:
        iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_access_key_if_exists(iam, user_name: str, access_key_id: str) -> None:
    try:
        iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
