"""backup-event-triggers-lambda-remediation."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "backup-event-triggers-lambda-remediation"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Backup Job State Change event with state FAILED, from a real job whose role holds no backup
    permissions, invokes the rule's Lambda target, which receives and forwards the failure
    detail."""
    events = ctx.client("events")
    lam = ctx.client("lambda")
    backup = ctx.client("backup")

    forward_queue = _create_plain_queue(ctx)
    func_name, func_arn = _create_forwarder_lambda(ctx, forward_queue["url"], forward_queue["arn"])

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {
        "source": ["aws.backup"],
        "detail-type": ["Backup Job State Change"],
        "detail": {"state": ["FAILED"]},
    }
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": func_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t1"]))

    lam.add_permission(
        FunctionName=func_name,
        StatementId="AllowEventBridgeInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )

    table_name, table_arn = _create_table(ctx)
    vault_name, _vault_arn = _create_vault(ctx)
    # Trusts backup.amazonaws.com (so AWS Backup CAN assume it and create the job) but
    # has NO permissions attached at all, so the job fails during execution with an
    # authorization error -- a real, deterministic FAILED transition.
    noperm_role_arn = _create_noperm_backup_role(ctx)

    job_id = _start_backup_job_with_retry(backup, vault_name, table_arn, noperm_role_arn)

    forwarded = _wait_for_event_matching(
        ctx, forward_queue["url"], lambda evt: evt.get("detail", {}).get("backupJobId") == job_id, timeout_s=220.0, interval_s=5.0
    )
    assert forwarded["detail"]["state"] == "FAILED", (
        f"expected the forwarded detail.state to be FAILED, got {forwarded['detail'].get('state')!r}"
    )
    assert forwarded["detail"].get("backupJobId") == job_id, (
        f"expected the forwarded detail.backupJobId to be {job_id!r}, got {forwarded['detail'].get('backupJobId')!r}"
    )
    assert forwarded["detail"].get("statusMessage"), (
        f"expected a non-empty failure statusMessage in the forwarded detail, got {forwarded['detail'].get('statusMessage')!r}"
    )


_FORWARDER_CODE = textwrap.dedent(
    """
    import json
    import os
    import boto3

    def handler(event, context):
        sqs = boto3.client("sqs")
        sqs.send_message(QueueUrl=os.environ["FORWARD_QUEUE_URL"], MessageBody=json.dumps(event))
        return {"forwarded": True}
    """
)


def _lambda_zip_bytes(handler_body: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_body)
    return buf.getvalue()


def _create_forwarder_lambda(ctx, queue_url: str, queue_arn: str) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-lmbrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="forward-sqs",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="forward-sqs"))

    func_name = ctx.unique_name("sim2real-fwd-")
    zip_bytes = _lambda_zip_bytes(_FORWARDER_CODE)

    deadline = time.monotonic() + 90.0
    last_exc: Exception | None = None
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": {"FORWARD_QUEUE_URL": queue_url}},
                Tags={"sim2real-check": CHECK},
            )
            break
        except ClientError as exc:
            # IAM is eventually consistent -- retry until the freshly created role is assumable.
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                last_exc = exc
                time.sleep(3.0)
                continue
            raise
    if resp is None:
        raise AssertionError(f"CreateFunction never succeeded within 90s: {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))

    def _probe():
        return lam.get_function(FunctionName=func_name)["Configuration"]["State"]

    _poll_until(_probe, lambda s: s == "Active", timeout_s=60.0, interval_s=2.0, description="lambda Active")
    return func_name, resp["FunctionArn"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_plain_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-fwdq-"), tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-bkuptbl-")
    resp = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name, resp["TableDescription"]["TableArn"]


def _create_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-bkupvault-")
    resp = backup.create_backup_vault(
        BackupVaultName=name, BackupVaultTags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: _cleanup_vault(backup, name))
    return name, resp["BackupVaultArn"]


def _cleanup_vault(backup, vault_name: str) -> None:
    try:
        rps = backup.list_recovery_points_by_backup_vault(BackupVaultName=vault_name).get(
            "RecoveryPoints", []
        )
        for rp in rps:
            try:
                backup.delete_recovery_point(
                    BackupVaultName=vault_name, RecoveryPointArn=rp["RecoveryPointArn"]
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        backup.delete_backup_vault(BackupVaultName=vault_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_noperm_backup_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-noperm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _start_backup_job_with_retry(
    backup, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 90.0
) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return backup.start_backup_job(
                BackupVaultName=vault_name, ResourceArn=resource_arn, IamRoleArn=role_arn
            )["BackupJobId"]
        except ClientError as exc:
            # IAM is eventually consistent -- retry until AWS Backup can assume the
            # freshly created role. A permission failure surfaces later, asynchronously,
            # once the job actually executes -- never here at StartBackupJob time.
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                last_exc = exc
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"start_backup_job never succeeded within {timeout_s}s (IAM propagation?): {last_exc}")


def _wait_for_event_matching(
    ctx, queue_url: str, match_fn, timeout_s: float = 90.0, interval_s: float = 3.0
) -> dict[str, Any]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                return body
        time.sleep(max(0.0, interval_s - 10.0))
    raise AssertionError(f"no matching event arrived on {queue_url} within {timeout_s}s")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
