"""cli-s3-upload-lambda-reads-config-secret-writes-dynamodb."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-s3-upload-lambda-reads-config-secret-writes-dynamodb"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An `aws s3 cp` upload fires an S3 ObjectCreated notification to a Lambda function
    that reads a processing-rules config from Secrets Manager, classifies the object
    against the secret's threshold, and records the classification in DynamoDB."""
    require_tools("aws")

    sm = ctx.client("secretsmanager")
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")

    config = {"size_threshold_bytes": 10, "large_category": "large", "small_category": "small"}
    secret_name = ctx.unique_name("sim2real-proc-config-")
    secret_arn = sm.create_secret(Name=secret_name, SecretString=json.dumps(config))["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    table_name = ctx.unique_name("sim2real-proc-table-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "object_key", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "object_key", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ctx, table_name)

    bucket = _create_bucket(ctx)

    role_arn = _create_lambda_role(
        ctx,
        [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": secret_arn},
            {
                "Effect": "Allow",
                "Action": ["dynamodb:PutItem"],
                "Resource": f"arn:aws:dynamodb:{ctx.region}:*:table/{table_name}",
            },
        ],
    )

    handler_code = (
        "import boto3, os, json\n"
        "def handler(event, context):\n"
        "    s3 = boto3.client('s3')\n"
        "    sm = boto3.client('secretsmanager')\n"
        "    ddb = boto3.client('dynamodb')\n"
        "    cfg = json.loads(sm.get_secret_value(SecretId=os.environ['SECRET_ID'])['SecretString'])\n"
        "    for record in event['Records']:\n"
        "        bkt = record['s3']['bucket']['name']\n"
        "        key = record['s3']['object']['key']\n"
        "        head = s3.head_object(Bucket=bkt, Key=key)\n"
        "        size = head['ContentLength']\n"
        "        category = cfg['large_category'] if size > cfg['size_threshold_bytes'] else cfg['small_category']\n"
        "        ddb.put_item(TableName=os.environ['TABLE_NAME'], Item={\n"
        "            'object_key': {'S': key},\n"
        "            'size': {'N': str(size)},\n"
        "            'category': {'S': category},\n"
        "        })\n"
        "    return {'processed': len(event['Records'])}\n"
    )
    fn_name = _create_function(
        ctx, role_arn, handler_code, env_vars={"SECRET_ID": secret_arn, "TABLE_NAME": table_name}
    )

    lam = ctx.client("lambda")
    fn_arn = lam.get_function(FunctionName=fn_name)["Configuration"]["FunctionArn"]
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="allowS3Invoke",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn=f"arn:aws:s3:::{bucket}",
        SourceAccount=account_id,
    )
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "LambdaFunctionConfigurations": [
                {"LambdaFunctionArn": fn_arn, "Events": ["s3:ObjectCreated:*"]}
            ]
        },
    )

    key = "docs/" + ctx.unique_name("upload-") + ".txt"
    content = b"X" * 25  # exceeds the 10-byte threshold -> "large"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(content)
        local_path = f.name
    try:
        _run_aws(ctx, "s3", "cp", local_path, f"s3://{bucket}/{key}")
    finally:
        os.unlink(local_path)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    item = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        resp = ddb.get_item(TableName=table_name, Key={"object_key": {"S": key}})
        if "Item" in resp:
            item = resp["Item"]
            break
        time.sleep(3)
    assert item is not None, "S3 upload never triggered a DynamoDB write via the Lambda notification"
    assert item["size"]["N"] == str(len(content)), item
    assert item["category"]["S"] == "large", item


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-proc-bucket-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _wait_table_active(ctx, table_name, timeout_s=60.0):
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _make_zip(handler_code: str, filename="index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_statements, role_name=None):
    iam = ctx.client("iam")
    role_name = role_name or ctx.unique_name("sim2real-lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    if policy_statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_function(ctx, role_arn, handler_code, handler="index.handler", env_vars=None, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _make_zip(handler_code)
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": zip_bytes},
        Timeout=timeout,
        Publish=False,
    )
    if env_vars:
        kwargs["Environment"] = {"Variables": env_vars}
    last_err = None
    for _ in range(8):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(5)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_for_active(ctx, name)
    return name


def _wait_for_active(ctx, name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


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
