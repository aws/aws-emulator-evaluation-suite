"""lambda-secretsmanager-fetched-config-drives-dynamodb-write."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-secretsmanager-fetched-config-drives-dynamodb-write"
_TAG_KV = [{"Key": "sim2real", "Value": CHECK}]
_TAG_DICT = {"sim2real": CHECK}
GROUP = "event-propagation"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager", "sqs"]

_HANDLER_CODE = """
import boto3, json, os

def handler(event, context):
    sm = boto3.client("secretsmanager")
    resp = sm.get_secret_value(SecretId=os.environ["SECRET_ARN"])
    config = json.loads(resp["SecretString"])
    suffix = config["item_suffix"]
    value = f"derived-{suffix}"

    ddb = boto3.client("dynamodb")
    ddb.put_item(
        TableName=os.environ["TABLE_NAME"],
        Item={"id": {"S": event["id"]}, "value": {"S": value}},
    )
    boto3.client("s3").put_object(
        Bucket=os.environ["BUCKET_NAME"], Key=event["id"], Body=value.encode("utf-8")
    )
    boto3.client("sqs").send_message(QueueUrl=os.environ["QUEUE_URL"], MessageBody=value)
    return {"written_value": value}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A function derives a value from a secret's JSON and writes it to DynamoDB, S3 and SQS; each sink, read
    back on its own, holds exactly that value, and every resource reads as gone after its delete.
    """
    suffix = "config-" + ctx.unique_name("")
    secret_arn = _create_secret(ctx, json.dumps({"item_suffix": suffix}))
    secret_name = ctx.client("secretsmanager").describe_secret(SecretId=secret_arn)["Name"]
    table_name, table_arn = _create_table(ctx)
    bucket = _create_bucket(ctx)
    queue_name, queue_url, queue_arn = _create_queue(ctx)

    role_arn, role_name = _create_role(
        ctx,
        [
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn},
            {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn},
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
        ],
    )
    fn_name = _create_function(
        ctx,
        role_arn,
        _HANDLER_CODE,
        env={
            "SECRET_ARN": secret_arn,
            "TABLE_NAME": table_name,
            "BUCKET_NAME": bucket,
            "QUEUE_URL": queue_url,
        },
    )

    resp, body = _invoke(ctx, fn_name, {"id": "row1"})
    assert resp.get("FunctionError") is None, f"unexpected FunctionError: {body}"
    expected_value = f"derived-{suffix}"
    assert body["written_value"] == expected_value, (
        f"handler's own return value: expected {expected_value!r}, got {body.get('written_value')!r}"
    )

    ddb = ctx.client("dynamodb")
    item = ddb.get_item(
        TableName=table_name, Key={"id": {"S": "row1"}}, ConsistentRead=True
    ).get("Item")
    assert item is not None, "item was never written to DynamoDB"
    assert item["value"]["S"] == expected_value, (
        f"independent GetItem: expected value {expected_value!r}, got {item['value']['S']!r}"
    )
    obj = ctx.client("s3").get_object(Bucket=bucket, Key="row1")["Body"].read().decode("utf-8")
    assert obj == expected_value, f"independent GetObject: expected {expected_value!r}, got {obj!r}"
    sqs = ctx.client("sqs")
    got = []
    deadline = time.monotonic() + 60
    while not got and time.monotonic() < deadline:
        got = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get(
            "Messages", []
        )
    assert [m["Body"] for m in got] == [expected_value], (
        f"independent ReceiveMessage: expected one body {expected_value!r}, got "
        f"{[m['Body'] for m in got]!r}"
    )

    # Tear down in reverse dependency order and prove each resource gone.
    _gone_lambda(ctx, fn_name)
    _gone_role(ctx, role_name)
    _gone_secret(ctx, secret_arn, secret_name)
    _gone_table(ctx, table_name, {"id": {"S": "row1"}, "value": {"S": "x"}})
    _gone_bucket(ctx, bucket)
    _gone_queue(ctx, queue_name, queue_url)


def _create_role(ctx: Any, statements: list[dict]) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAG_KV
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(_tolerant(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(
        _tolerant(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn),
            "NoSuchEntity",
        )
    )

    if statements:
        policy_name = ctx.unique_name("sim2real-lambda-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(
            _tolerant(
                lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name),
                "NoSuchEntity",
            )
        )
    return role_arn, role_name


def _create_function(
    ctx: Any, role_arn: str, handler_code: str, env: dict | None = None, timeout: int = 30
) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", handler_code)
    zip_bytes = buf.getvalue()

    last_err: Exception | None = None
    deadline = time.monotonic() + 90
    created = False
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    while time.monotonic() < deadline:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags=_TAG_DICT,
            )
            created = True
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if not created:
        raise AssertionError(f"function creation never succeeded (role propagation): {last_err}")

    ctx.on_cleanup(_tolerant(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    _wait_function_active(ctx, name)
    return name


def _wait_function_active(ctx: Any, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _invoke(ctx: Any, name: str, payload: dict | None = None) -> tuple[dict, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode("utf-8"),
    )
    body = json.loads(resp["Payload"].read())
    return resp, body


def _create_secret(ctx: Any, secret_string: str, kms_key_id: str | None = None) -> str:
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-secret-")
    kwargs: dict[str, Any] = {"Name": name, "SecretString": secret_string, "Tags": _TAG_KV}
    if kms_key_id:
        kwargs["KmsKeyId"] = kms_key_id
    resp = sm.create_secret(**kwargs)
    arn = resp["ARN"]
    ctx.on_cleanup(
        _tolerant(
            lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True),
            "ResourceNotFoundException",
        )
    )
    return arn


def _create_table(ctx: Any) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-table-")
    resp = ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_TAG_KV,
    )
    table_arn = resp["TableDescription"]["TableArn"]
    ctx.on_cleanup(_tolerant(lambda: ddb.delete_table(TableName=table_name), "ResourceNotFoundException"))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if ddb.describe_table(TableName=table_name)["Table"]["TableStatus"] == "ACTIVE":
            return table_name, table_arn
        time.sleep(2)
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, names: str | None = None) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status``, a non-empty message naming ``names``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg.strip(), f"{what}: {code} carries an empty message"
        if names:
            assert names in msg, f"{what}: {code} message does not name {names!r}: {msg[:200]!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, names=None, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, names)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


_SQS_NF = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")


def _gone_secret(ctx, arn: str, name: str) -> None:
    sm = ctx.client("secretsmanager")
    sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: sm.describe_secret(SecretId=arn), nf, 400, f"DescribeSecret {name}")
    listed = {s["ARN"] for s in _paged(sm, "list_secrets", "SecretList", Filters=[{"Key": "name", "Values": [name]}])}
    assert arn not in listed, f"ListSecrets still lists deleted secret {name}"
    _refused(lambda: sm.put_secret_value(SecretId=arn, SecretString="gone"), nf, 400, f"PutSecretValue {name}")


def _gone_lambda(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_function(FunctionName=name)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: lam.get_function(FunctionName=name), nf, 404, f"GetFunction {name}", name)
    listed = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
    assert name not in listed, f"ListFunctions still lists deleted function {name}"
    _refused(lambda: lam.invoke(FunctionName=name, Payload=b"{}"), nf, 404, f"Invoke {name}", name)


def _gone_role(ctx, name: str, path: str = "/") -> None:
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}", name)
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=path)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}",
    )


def _gone_table(ctx, name: str, item: dict) -> None:
    ddb = ctx.client("dynamodb")
    ddb.delete_table(TableName=name)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: ddb.describe_table(TableName=name), nf, 400, f"DescribeTable {name}", name)
    assert name not in _paged(ddb, "list_tables", "TableNames"), f"ListTables still lists deleted table {name}"
    _refused(lambda: ddb.put_item(TableName=name, Item=item), nf, 400, f"PutItem {name}")


def _empty_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})


def _gone_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    _empty_bucket(s3, bucket)
    s3.delete_bucket(Bucket=bucket)
    # HeadBucket has no body: the code is the bare status.
    _poll_refused(lambda: s3.head_bucket(Bucket=bucket), ("404", "NoSuchBucket", "NotFound"), 404, f"HeadBucket {bucket}")
    names = {b["Name"] for b in s3.list_buckets(Prefix=bucket).get("Buckets", [])}
    assert bucket not in names, f"ListBuckets still lists deleted bucket {bucket}"
    _refused(lambda: s3.put_object(Bucket=bucket, Key="gone", Body=b"x"), ("NoSuchBucket",), 404, f"PutObject {bucket}")


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # AWS documents up to 60 s for a deleted queue to stop answering.
    _poll_refused(lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}")
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {name}")


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bkt-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's region-less default and rejects naming itself.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _drop() -> None:
        _empty_bucket(s3, name)
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_tolerant(_drop, "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _TAG_KV})
    return name


def _create_queue(ctx: Any) -> tuple[str, str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-q-")
    url = sqs.create_queue(QueueName=name, tags=_TAG_DICT)["QueueUrl"]
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=url), *_SQS_NF))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return name, url, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
