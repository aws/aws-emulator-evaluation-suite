"""delete-model-invocation-logging-config-clears-server-state."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-model-invocation-logging-config-clears-server-state"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:bedrock-invocation-logging")
def run(ctx) -> None:
    """A CloudWatch Logs invocation-logging config written by Put is reported by Get, and after
    DeleteModelInvocationLoggingConfiguration Get reports no config: the delete clears state."""
    bedrock = ctx.client("bedrock")
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    original = bedrock.get_model_invocation_logging_configuration()
    original_config = original.get("loggingConfig")

    def _restore():
        if original_config is not None:
            bedrock.put_model_invocation_logging_configuration(loggingConfig=original_config)
        else:
            bedrock.delete_model_invocation_logging_configuration()

    ctx.on_cleanup(_restore)

    log_group_name = ctx.unique_name("sim2real-bedrock-logs-")
    logs.create_log_group(logGroupName=log_group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _delete_log_group_best_effort(ctx, log_group_name))

    role_name = ctx.unique_name("sim2real-bedrock-logs-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "bedrock.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {"aws:SourceAccount": account_id},
                "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock:{ctx.region}:{account_id}:*"},
            },
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_best_effort(ctx, role_name))

    log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_name}:*"
    access_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": log_group_arn,
        }],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="logs-access", PolicyDocument=json.dumps(access_policy)
    )

    # CloudWatch Logs, not S3: Bedrock's S3 bucket-policy validation can reject a correct policy.
    def _put_logging_config():
        bedrock.put_model_invocation_logging_configuration(
            loggingConfig={
                "cloudWatchConfig": {"logGroupName": log_group_name, "roleArn": role_arn},
                "textDataDeliveryEnabled": True,
            }
        )

    try:
        _retry_until_no_transient_error(_put_logging_config, timeout_s=60.0, interval_s=10.0)
    except _PermissionWall as exc:
        raise AssertionError(
            "this sandbox account rejects Bedrock's role assumption / bucket "
            f"validation path independent of configuration correctness: {exc}"
        )

    after_put = bedrock.get_model_invocation_logging_configuration()
    put_log_group_name = after_put["loggingConfig"]["cloudWatchConfig"]["logGroupName"]
    assert put_log_group_name == log_group_name, (
        f"expected logging config to report log group {log_group_name!r}, got {put_log_group_name!r}"
    )

    bedrock.delete_model_invocation_logging_configuration()

    after_delete = bedrock.get_model_invocation_logging_configuration()
    assert not after_delete.get("loggingConfig"), (
        f"expected no logging config after delete, got {after_delete.get('loggingConfig')}"
    )


class _PermissionWall(Exception):
    pass


def _retry_until_no_transient_error(fn, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            message = getattr(exc, "response", {}).get("Error", {}).get("Message", "")
            if code == "AccessDeniedException" and "pass role" in message.lower():
                raise _PermissionWall(f"{code}: {message}")
            if code != "ValidationException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"logging config did not accept the role/log-group within {timeout_s}s: {last_exc}")


def _delete_log_group_best_effort(ctx, log_group_name: str) -> None:
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_role_best_effort(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="logs-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
