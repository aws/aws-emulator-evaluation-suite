"""get-web-identity-token-session-duration-escalation-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-web-identity-token-session-duration-escalation-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:iam-outbound-web-identity-federation")
def run(ctx) -> None:
    """From a 900s assumed-role session, a 3600s GetWebIdentityToken JWT is refused with
    SessionDurationEscalationException and its exact message, repeatably; a 60s JWT succeeds.
    """
    iam = ctx.client("iam")
    sts_admin = ctx.client("sts")

    original_enabled = _federation_enabled(iam)
    ctx.on_cleanup(lambda: _set_federation_enabled(iam, original_enabled))
    _set_federation_enabled(iam, True)

    account_id = sts_admin.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-swidt-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = ctx.unique_name("sim2real-swidt-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sts:GetWebIdentityToken",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    # A new role's trust policy takes a few seconds to propagate.
    assumed = _poll_until(
        lambda: _try_assume_role(sts_admin, role_arn),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    creds = assumed["Credentials"]
    limited_sts = ctx.client("sts", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })

    audience = [f"https://{ctx.unique_name('sim2real-swidt-aud-')}.example.com"]

    def _escalated_call():
        return limited_sts.get_web_identity_token(
            Audience=audience, SigningAlgorithm="RS256", DurationSeconds=3600
        )

    # 3600s exceeds the session's remaining ~900s. The inline permissions policy propagates
    # separately from the trust policy, so poll past an initial AccessDenied.
    code, message = _poll_until(
        lambda: _refusal(_escalated_call),
        lambda r: r[0] != "AccessDenied",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert code == "SessionDurationEscalationException", (
        f"expected SessionDurationEscalationException for a JWT duration exceeding "
        f"the caller's remaining session lifetime, got {code!r}"
    )
    expected_message = "Requested token expiry time must be before the original session's expiry time."
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )

    # Effect absent: repeating the escalated request still fails the same way.
    again = _refusal(_escalated_call)
    assert again == (code, expected_message), (
        f"expected the repeated escalated request to fail identically, got {again!r}"
    )

    # Positive control: an in-bounds duration on the same session.
    resp = limited_sts.get_web_identity_token(
        Audience=audience, SigningAlgorithm="RS256", DurationSeconds=60
    )
    assert resp["WebIdentityToken"], (
        f"expected a JWT for an in-bounds duration on the same session, got {resp!r}"
    )


def _refusal(fn):
    """The (code, message) of a refused call; raises when the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _federation_enabled(iam) -> bool:
    try:
        info = iam.get_outbound_web_identity_federation_info()
    except ClientError as e:
        if e.response["Error"]["Code"] == "FeatureDisabled":
            return False
        raise
    return bool(info.get("JwtVendingEnabled", False))


def _set_federation_enabled(iam, enabled: bool) -> None:
    current = _federation_enabled(iam)
    if enabled and not current:
        try:
            iam.enable_outbound_web_identity_federation()
        except ClientError as e:
            if e.response["Error"]["Code"] != "FeatureEnabled":
                raise
    elif not enabled and current:
        try:
            iam.disable_outbound_web_identity_federation()
        except ClientError as e:
            if e.response["Error"]["Code"] != "FeatureDisabled":
                raise


def _try_assume_role(sts_client, role_arn: str):
    try:
        return sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="sim2real-swidt-session",
            DurationSeconds=900,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return None
        raise


def _poll_until(probe, predicate, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError("condition not met within timeout")
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
