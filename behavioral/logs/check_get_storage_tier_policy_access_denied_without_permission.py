"""get-storage-tier-policy-access-denied-without-permission."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-storage-tier-policy-access-denied-without-permission"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetStorageTierPolicy (an account-level setting) is AccessDenied for a role with no grant,
    and the identical call succeeds once logs:GetStorageTierPolicy is granted.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cwl_intelligent_tier.html
    """
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: the privileged caller's read works.
    baseline = logs.get_storage_tier_policy()["storageTier"]
    assert baseline in ("STANDARD", "INTELLIGENT_TIERING"), (
        f"expected the privileged caller's GetStorageTierPolicy to succeed as a positive "
        f"control, got {baseline!r}"
    )

    role_name = ctx.unique_name("sim2real-behav-noperm-")
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    session_name = "sim2real-behav-session"
    unprivileged_logs = _assume_role_client(ctx, role_arn, "logs", session_name)

    code, message = _error(lambda: unprivileged_logs.get_storage_tier_policy())
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for GetStorageTierPolicy with no permissions, got {code}"
    )
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: logs:GetStorageTierPolicy on resource: "
        f"arn:aws:logs:{ctx.region}:{account_id}:log-group:* because no "
        "identity-based policy allows the logs:GetStorageTierPolicy action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_denial = logs.get_storage_tier_policy()["storageTier"]
    assert after_denial == baseline, (
        f"a denied GetStorageTierPolicy must have zero side effect on the account setting: "
        f"baseline was {baseline!r}, now {after_denial!r}"
    )

    # IAM grants are eventually consistent, hence the poll.
    policy_name = "sim2real-behav-allow-get-storage-tier-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "logs:GetStorageTierPolicy",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    restored = _poll_until_success(
        lambda: unprivileged_logs.get_storage_tier_policy()["storageTier"],
        timeout_s=60.0,
        interval_s=3.0,
        description="the grant of logs:GetStorageTierPolicy propagates to the assumed role",
    )
    assert restored in ("STANDARD", "INTELLIGENT_TIERING"), (
        f"expected GetStorageTierPolicy to succeed once the role is granted the permission, "
        f"got {restored!r}"
    )


def _poll_until_success(fn, *, timeout_s: float, interval_s: float, description: str):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s: {last_err!r}")


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _assume_role_client(ctx, role_arn: str, service: str, session_name: str):
    sts = ctx.client("sts")
    deadline = time.monotonic() + 45.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name
            )["Credentials"]
            return ctx.client(
                service,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except Exception as exc:  # noqa: BLE001 - role trust propagation retry
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"could not assume role {role_arn} after retries: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
