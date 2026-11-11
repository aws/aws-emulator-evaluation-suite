"""get-web-identity-token-duration-escalation-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-web-identity-token-duration-escalation-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx: Any) -> None:
    """GetWebIdentityToken rejects a JWT DurationSeconds outliving the assumed-role session with
    SessionDurationEscalationException and its exact message; a shorter one succeeds."""
    iam_for_federation = ctx.client("iam")
    _ensure_federation_enabled(ctx, iam_for_federation)

    role_arn = _create_assumable_role(ctx)
    sts = ctx.client("sts")
    resp = _wait_for_assume_role(
        sts,
        RoleArn=role_arn,
        RoleSessionName=ctx.unique_name("behav-sess-")[:64],
        DurationSeconds=900,  # AWS-enforced minimum session duration
    )
    creds = resp["Credentials"]
    session_client = _sts_client_with_creds(ctx, creds)

    # Ask for a JWT that would outlive the 900s session. A just-minted session is briefly
    # not resolvable by GetWebIdentityToken (AccessDenied), so the helper retries that code.
    bad_resp, code, message = _get_web_identity_token(
        session_client,
        Audience=["https://sim2real.example.com"],
        SigningAlgorithm="RS256",
        DurationSeconds=3600,
    )
    if bad_resp is not None:
        raise AssertionError(
            f"expected SessionDurationEscalationException, call succeeded: {bad_resp}"
        )
    # The error Code carries the "Exception" suffix although the API reference names it
    # "SessionDurationEscalation".
    assert code == "SessionDurationEscalationException", f"unexpected code: {code}"
    expected_message = "Requested token expiry time must be before the original session's expiry time."
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )

    # Positive control: the same session with a duration within its remaining validity.
    ok_resp, ok_code, _ok_message = _get_web_identity_token(
        session_client,
        Audience=["https://sim2real.example.com"],
        SigningAlgorithm="RS256",
        DurationSeconds=60,
    )
    assert ok_resp is not None, f"expected success, got error code: {ok_code}"
    assert ok_resp.get("WebIdentityToken")


def _get_web_identity_token(client: Any, timeout_s: float = 30.0, **kwargs: Any):
    """(resp, code, message) of the call. Retries only AccessDenied, which also covers the
    eventually consistent "Caller identity could not be resolved"; other codes are terminal."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return client.get_web_identity_token(**kwargs), None, None
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDenied" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            return None, code, exc.response["Error"].get("Message")


def _ensure_federation_enabled(ctx: Any, iam: Any) -> None:
    """Enable the account-level, off-by-default outbound web-identity federation if needed,
    restoring the original state at cleanup."""
    original_enabled = _federation_enabled(iam)
    ctx.on_cleanup(lambda: _set_federation_enabled(iam, original_enabled))
    if not original_enabled:
        iam.enable_outbound_web_identity_federation()
        # The IAM flag reaches STS with a delay; poll GetWebIdentityToken itself.
        sts = ctx.client("sts")
        deadline = time.monotonic() + 30
        last_code: str | None = None
        while time.monotonic() < deadline:
            try:
                sts.get_web_identity_token(
                    Audience=["https://sim2real.example.com"],
                    SigningAlgorithm="RS256",
                    DurationSeconds=60,
                )
                return
            except ClientError as exc:
                last_code = exc.response["Error"]["Code"]
                if last_code != "OutboundWebIdentityFederationDisabledException":
                    return
                time.sleep(2)
        raise AssertionError(
            f"outbound web identity federation still disabled 30s after enabling "
            f"(last_code={last_code})"
        )


def _federation_enabled(iam: Any) -> bool:
    try:
        info = iam.get_outbound_web_identity_federation_info()
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("FeatureDisabledException", "FeatureDisabled"):
            return False
        raise
    return bool(info.get("JwtVendingEnabled", False))


def _set_federation_enabled(iam: Any, enabled: bool) -> None:
    current = _federation_enabled(iam)
    if enabled and not current:
        iam.enable_outbound_web_identity_federation()
    elif not enabled and current:
        iam.disable_outbound_web_identity_federation()


def _create_assumable_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]
    role_name = ctx.unique_name("sim2real-behav-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": caller_arn}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # Without this permission every call is AccessDenied, masking the escalation error.
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "sts:GetWebIdentityToken", "Resource": "*"}
        ],
    }
    policy_name = ctx.unique_name("sim2real-behav-pol-")[:128]
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    deadline = time.monotonic() + 30
    last_code: str | None = None
    while time.monotonic() < deadline:
        try:
            sts.assume_role(RoleArn=role_arn, RoleSessionName="probe", DurationSeconds=900)
            return role_arn
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            time.sleep(2)
    raise AssertionError(f"role never became assumable within 30s (last_code={last_code})")


def _sts_client_with_creds(ctx: Any, creds: dict) -> Any:
    return ctx.client("sts", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _wait_for_assume_role(sts_client, timeout_s: float = 30.0, interval_s: float = 2.0, **kwargs):
    """Poll AssumeRole: trust-policy propagation is eventually consistent even after one
    earlier AssumeRole succeeded."""
    deadline = time.monotonic() + timeout_s
    last_err: str | None = None
    while time.monotonic() < deadline:
        try:
            return sts_client.assume_role(**kwargs)
        except ClientError as exc:
            last_err = exc.response["Error"]["Code"]
            time.sleep(interval_s)
    raise AssertionError(f"assume_role never became permitted within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
