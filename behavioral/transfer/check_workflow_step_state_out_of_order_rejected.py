"""workflow-step-state-out-of-order-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "workflow-step-state-out-of-order-rejected"
GROUP = "ordering"
SERVICES = ["transfer"]

from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding as _Encoding,
    NoEncryption as _NoEncryption,
    PrivateFormat as _PrivateFormat,
    PublicFormat as _PublicFormat,
)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendWorkflowStepState replaying the token of an already-completed step fails with
    ResourceNotFoundException "Unknown execution" and does not change DescribeExecution's answer."""

    transfer = ctx.client("transfer")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    s3 = ctx.client("s3")
    secretsmanager = ctx.client("secretsmanager")

    bucket = ctx.unique_name("sim2real-behav-wf-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    lambda_role_arn = _create_role(
        ctx,
        iam,
        "sim2real-behav-wf-lambdarole-",
        "lambda.amazonaws.com",
        managed_policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
    )
    iam.put_role_policy(
        RoleName=lambda_role_arn.split("/")[-1],
        PolicyName="marker-and-report",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/tokens/*"},
                    {"Effect": "Allow", "Action": "transfer:SendWorkflowStepState", "Resource": "*"},
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=lambda_role_arn.split("/")[-1], PolicyName="marker-and-report")
    )

    function_name = ctx.unique_name("sim2real-behav-wf-fn-")
    code_zip = _lambda_zip_bytes(_LAMBDA_SOURCE)
    function_arn = _create_lambda_function(ctx, lam, function_name, lambda_role_arn, code_zip, bucket)

    workflow_exec_role_arn = _create_role(
        ctx, iam, "sim2real-behav-wf-execrole-", "transfer.amazonaws.com"
    )
    iam.put_role_policy(
        RoleName=workflow_exec_role_arn.split("/")[-1],
        PolicyName="invoke-lambda",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function_arn}],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=workflow_exec_role_arn.split("/")[-1], PolicyName="invoke-lambda")
    )

    user_role_arn = _create_role(
        ctx,
        iam,
        "sim2real-behav-wf-userrole-",
        "transfer.amazonaws.com",
        inline_statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    )
    connector_role_arn = _create_role(
        ctx,
        iam,
        "sim2real-behav-wf-connrole-",
        "transfer.amazonaws.com",
        inline_statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "arn:aws:secretsmanager:*:*:secret:aws/transfer/*",
            },
        ],
    )

    workflow_id = transfer.create_workflow(
        Steps=[
            {
                "Type": "CUSTOM",
                "CustomStepDetails": {
                    "Name": "pause",
                    "Target": function_arn,
                    "TimeoutSeconds": 300,
                    "SourceFileLocation": "${original.file}",
                },
            }
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["WorkflowId"]
    ctx.on_cleanup(lambda: transfer.delete_workflow(WorkflowId=workflow_id))

    host_private_pem, _ = _generate_rsa_keypair()
    server_id = transfer.create_server(
        Protocols=["SFTP"], HostKey=host_private_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    transfer.update_server(
        ServerId=server_id,
        WorkflowDetails={"OnUpload": [{"WorkflowId": workflow_id, "ExecutionRole": workflow_exec_role_arn}]},
    )

    user_private_pem, user_public_openssh = _generate_rsa_keypair()
    username = ctx.unique_name("sim2realuser").replace("-", "")[:32]
    transfer.create_user(
        ServerId=server_id,
        UserName=username,
        Role=user_role_arn,
        HomeDirectoryType="PATH",
        HomeDirectory=f"/{bucket}",
        SshPublicKeyBody=user_public_openssh,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=username))

    transfer.start_server(ServerId=server_id)
    ctx.on_cleanup(lambda: _best_effort_stop(transfer, server_id))
    _poll_until(
        probe=lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
        predicate=lambda s: s == "ONLINE",
        timeout_s=400,
        interval_s=5,
    )

    # An outbound SFTP connector authenticating as the user against this server performs a
    # real SFTP PUT that fires the OnUpload workflow, with no external SSH client.
    secret_name = ctx.unique_name("aws/transfer/sim2real-behav-wf-")
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"Username": username, "PrivateKey": user_private_pem}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    trigger_key = "trigger.txt"
    s3.put_object(Bucket=bucket, Key=trigger_key, Body=b"sim2real workflow trigger fixture\n")

    server_host = f"{server_id}.server.transfer.{ctx.region}.amazonaws.com"
    connector_id = transfer.create_connector(
        Url=f"sftp://{server_host}",
        AccessRole=connector_role_arn,
        SftpConfig={"UserSecretId": secret_arn},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ConnectorId"]
    ctx.on_cleanup(lambda: transfer.delete_connector(ConnectorId=connector_id))

    probe = _poll_until(
        probe=lambda: transfer.test_connection(ConnectorId=connector_id),
        predicate=lambda r: "SftpConnectionDetails" in r and r["SftpConnectionDetails"].get("HostKey"),
        timeout_s=180,
        interval_s=10,
    )
    host_key = probe["SftpConnectionDetails"]["HostKey"]
    transfer.update_connector(
        ConnectorId=connector_id,
        SftpConfig={"UserSecretId": secret_arn, "TrustedHostKeys": [host_key]},
    )
    test_result = _poll_until(
        probe=lambda: transfer.test_connection(ConnectorId=connector_id),
        predicate=lambda r: r["Status"] == "OK",
        timeout_s=120,
        interval_s=10,
    )
    assert test_result["Status"] == "OK", f"connector could not reach the server: {test_result.get('StatusMessage')}"

    transfer_id = transfer.start_file_transfer(
        ConnectorId=connector_id,
        SendFilePaths=[f"/{bucket}/{trigger_key}"],
        RemoteDirectoryPath=f"/{bucket}",
    )["TransferId"]

    transfer_result = _poll_until(
        probe=lambda: _first_transfer_result(transfer, connector_id, transfer_id),
        predicate=lambda r: r is not None and r["StatusCode"] in ("COMPLETED", "FAILED"),
        timeout_s=120,
        interval_s=5,
    )
    assert transfer_result["StatusCode"] == "COMPLETED", (
        f"the connector's own push failed: {transfer_result.get('FailureCode')} "
        f"{transfer_result.get('FailureMessage')}"
    )

    marker_key = _poll_until(
        probe=lambda: _first_marker_key(s3, bucket),
        predicate=lambda k: k is not None,
        timeout_s=60,
        interval_s=3,
    )
    marker = json.loads(s3.get_object(Bucket=bucket, Key=marker_key)["Body"].read())
    assert marker["workflowId"] == workflow_id, f"marker from an unrelated workflow: {marker!r}"
    execution_id = marker["executionId"]

    # Positive control: the Lambda's in-order SendWorkflowStepState succeeded, shown by the
    # ".done" marker it writes afterwards. A finished single-step execution disappears from
    # DescribeExecution/ListExecutions almost at once, so those cannot serve as evidence.
    _poll_until(
        probe=lambda: _done_marker_exists(s3, bucket, marker["token"]),
        predicate=lambda done: done,
        timeout_s=60,
        interval_s=3,
    )

    # Baseline read of the finished execution, compared against after the rejected replay.
    code_before = _outcome(lambda: transfer.describe_execution(WorkflowId=workflow_id, ExecutionId=execution_id))

    code, message = _error(
        lambda: transfer.send_workflow_step_state(
            WorkflowId=marker["workflowId"],
            ExecutionId=marker["executionId"],
            Token=marker["token"],
            Status="SUCCESS",
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Unknown execution", f"expected 'Unknown execution', got {message!r}"

    # The rejected replay did not resurrect or perturb the execution.
    code_after = _outcome(lambda: transfer.describe_execution(WorkflowId=workflow_id, ExecutionId=execution_id))
    assert code_after == code_before, (
        f"the rejected replay changed DescribeExecution's answer: before={code_before!r} after={code_after!r}"
    )


_LAMBDA_SOURCE = """
import json
import os
import boto3

s3 = boto3.client("s3")
transfer = boto3.client("transfer")


def lambda_handler(event, context):
    token = event["token"]
    workflow_id = event["serviceMetadata"]["executionDetails"]["workflowId"]
    execution_id = event["serviceMetadata"]["executionDetails"]["executionId"]
    marker = {"workflowId": workflow_id, "executionId": execution_id, "token": token}
    s3.put_object(
        Bucket=os.environ["MARKER_BUCKET"],
        Key="tokens/" + token + ".json",
        Body=json.dumps(marker).encode("utf-8"),
    )
    transfer.send_workflow_step_state(
        WorkflowId=workflow_id, ExecutionId=execution_id, Token=token, Status="SUCCESS"
    )
    s3.put_object(
        Bucket=os.environ["MARKER_BUCKET"],
        Key="tokens/" + token + ".done",
        Body=b"ok",
    )
    return {"ok": True}
"""


def _error(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, the call succeeded with {result!r}")


def _outcome(fn):
    """The error code fn raises, or "succeeded" when the call returns."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return "succeeded"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _best_effort_stop(transfer, server_id: str) -> None:
    try:
        transfer.stop_server(ServerId=server_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    resp = s3.list_objects_v2(Bucket=bucket)
    objects = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
    if objects:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _first_marker_key(s3, bucket: str):
    resp = s3.list_objects_v2(Bucket=bucket, Prefix="tokens/")
    json_keys = [o["Key"] for o in resp.get("Contents", []) if o["Key"].endswith(".json")]
    return json_keys[0] if json_keys else None


def _done_marker_exists(s3, bucket: str, token: str) -> bool:
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=f"tokens/{token}.done")
    return bool(resp.get("Contents"))


def _first_transfer_result(transfer, connector_id: str, transfer_id: str):
    resp = transfer.list_file_transfer_results(ConnectorId=connector_id, TransferId=transfer_id)
    results = resp.get("FileTransferResults", [])
    return results[0] if results else None


def _generate_rsa_keypair():
    private_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=_Encoding.PEM,
        format=_PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=_NoEncryption(),
    ).decode()
    public_openssh = private_key.public_key().public_bytes(
        encoding=_Encoding.OpenSSH, format=_PublicFormat.OpenSSH
    ).decode()
    return private_pem, public_openssh


def _create_role(ctx, iam, name_prefix: str, service_principal: str, managed_policy_arns=None, inline_statements=None) -> str:
    role_name = ctx.unique_name(name_prefix)[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p))
    if inline_statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
    _poll_until(
        probe=lambda: _iam_role_readable(iam, role_name, bool(inline_statements)),
        predicate=lambda ready: ready,
        timeout_s=30,
        interval_s=2,
    )
    return role_arn


def _iam_role_readable(iam, role_name: str, needs_inline_policy: bool) -> bool:
    try:
        iam.get_role(RoleName=role_name)
        if needs_inline_policy:
            iam.get_role_policy(RoleName=role_name, PolicyName="inline")
    except Exception:
        return False
    return True


def _lambda_zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_function(ctx, lam, function_name: str, role_arn: str, code_zip: bytes, bucket: str) -> str:
    deadline = time.monotonic() + 60
    last_error = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.lambda_handler",
                Code={"ZipFile": code_zip},
                Timeout=30,
                Environment={"Variables": {"MARKER_BUCKET": bucket}},
                Tags={"sim2real": CHECK},
            )
            break
        except Exception as exc:  # role not yet assumable by Lambda (IAM propagation)
            last_error = exc
            time.sleep(5)
    else:
        raise last_error
    function_arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _poll_until(
        probe=lambda: lam.get_function(FunctionName=function_name)["Configuration"]["State"],
        predicate=lambda st: st == "Active",
        timeout_s=60,
        interval_s=3,
    )
    return function_arn


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

