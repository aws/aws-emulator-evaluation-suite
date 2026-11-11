"""delete-model-invocation-logging-config-without-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-model-invocation-logging-config-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:bedrock-invocation-logging")
def run(ctx) -> None:
    """DeleteModelInvocationLoggingConfiguration from a principal with an explicit IAM Deny is
    refused with AccessDeniedException and leaves the logging config unchanged; the same call
    from a permitted principal succeeds."""
    bedrock = ctx.client("bedrock")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    logs = ctx.client("logs")

    original = bedrock.get_model_invocation_logging_configuration().get("loggingConfig")
    ctx.on_cleanup(
        lambda: bedrock.put_model_invocation_logging_configuration(loggingConfig=original)
        if original
        else bedrock.delete_model_invocation_logging_configuration()
    )

    account_id = sts.get_caller_identity()["Account"]

    # CloudWatch Logs delivery for the baseline config: an S3 destination would add Bedrock's
    # separate bucket-policy validation step as an unrelated prerequisite.
    log_group_name = ctx.unique_name("/sim2real/bedlog-noperm-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    delivery_role_name = ctx.unique_name("sim2real-bedlog-delivery-")
    delivery_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                },
            }
        ],
    }
    delivery_role = iam.create_role(
        RoleName=delivery_role_name,
        AssumeRolePolicyDocument=json.dumps(delivery_trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=delivery_role_name))
    delivery_role_arn = delivery_role["Role"]["Arn"]

    delivery_policy_name = "bedrock-logs-delivery"
    iam.put_role_policy(
        RoleName=delivery_role_name,
        PolicyName=delivery_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_name}:*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=delivery_role_name, PolicyName=delivery_policy_name)
    )

    # The delivery role's trust and permissions policies are eventually consistent;
    # poll the actual establishing call rather than trusting a fixed propagation delay.
    deadline = time.monotonic() + 40.0
    while True:
        try:
            bedrock.put_model_invocation_logging_configuration(
                loggingConfig={
                    "cloudWatchConfig": {"logGroupName": log_group_name, "roleArn": delivery_role_arn},
                    "textDataDeliveryEnabled": True,
                }
            )
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ValidationException" and time.monotonic() < deadline:
                time.sleep(5.0)  # delivery role propagation lag
                continue
            raise AssertionError(
                f"could not establish a baseline CloudWatch logging config for role "
                f"{delivery_role_arn!r} (same-account bedrock.amazonaws.com trust): "
                f"{code}: {err.response['Error'].get('Message', '')[-200:]}"
            ) from err
    baseline = bedrock.get_model_invocation_logging_configuration()["loggingConfig"]

    role_name = ctx.unique_name("sim2real-noperm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    low_priv_role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    # Explicit Deny makes the denial deterministic regardless of permissions fresh roles get.
    deny_policy_name = "deny-delete-logging-config"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=deny_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "bedrock:DeleteModelInvocationLoggingConfiguration",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=deny_policy_name))

    low_priv_bedrock = _assume_role_client(ctx, low_priv_role_arn, "bedrock")

    # The inline deny policy is eventually consistent: until it is in force the refusal is the
    # implicit-deny one, so poll until the explicit denial is observed.
    expected = (
        "AccessDeniedException",
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-noperm-session "
        "is not authorized to perform: bedrock:DeleteModelInvocationLoggingConfiguration "
        "with an explicit deny in an identity-based policy",
    )
    deadline = time.monotonic() + 60.0
    got = _error(lambda: low_priv_bedrock.delete_model_invocation_logging_configuration())
    while got != expected and time.monotonic() < deadline:
        time.sleep(3.0)
        got = _error(lambda: low_priv_bedrock.delete_model_invocation_logging_configuration())
    assert got == expected, (
        f"expected a principal with an explicit Deny to be refused with {expected!r}, got {got!r}"
    )

    unchanged = bedrock.get_model_invocation_logging_configuration()["loggingConfig"]
    assert unchanged["cloudWatchConfig"]["logGroupName"] == baseline["cloudWatchConfig"]["logGroupName"], (
        "expected the denied delete attempt to leave the logging configuration unchanged, "
        f"got {unchanged!r}"
    )

    # Positive control: the same delete from a permitted principal succeeds.
    bedrock.delete_model_invocation_logging_configuration()
    final = bedrock.get_model_invocation_logging_configuration().get("loggingConfig")
    assert not final, f"expected the admin delete to leave no logging config, got {final!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        e = err.response["Error"]
        return e["Code"], e.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _assume_role_client(ctx, role_arn, service_name, timeout_s=45.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-noperm-session")[
                "Credentials"
            ]
            return ctx.client(
                service_name,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] in ("AccessDenied", "AccessDeniedException"):
                time.sleep(3.0)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
