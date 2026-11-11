"""s3-to-sqs-to-lambda-pipeline-positive."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-to-sqs-to-lambda-pipeline-positive"

GROUP = "event-propagation"

SERVICES = ["cloudformation", "lambda", "s3", "sqs"]


def _msg_body_json(msg: dict) -> dict:
    """Return message body as a parsed dict, whether it arrives as str or dict."""
    raw = msg.get("Body") or msg.get("body", "{}")
    if isinstance(raw, dict):
        return raw
    return json.loads(raw)


def _drain_s3_test_events(sqs_client, queue_url: str, timeout_s: int = 15) -> None:
    """Drain S3 TestEvent messages that AWS sends when configuring bucket notifications.

    When a bucket notification is configured, S3 sends a 's3:TestEvent' to each destination.
    This helper drains those probe messages so checks only see real object events.
    """

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs_client.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=2,
        )
        msgs = resp.get("Messages", [])
        if not msgs:
            break
        for msg in msgs:
            raw = _msg_body_json(msg)
            # If it is a test event, delete it; otherwise leave it (shouldn't happen pre-PutObject)
            if raw.get("Event") == "s3:TestEvent" or raw.get("Service") == "Amazon S3":
                sqs_client.delete_message(
                    QueueUrl=queue_url,
                    ReceiptHandle=msg["ReceiptHandle"],
                )


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An object put in the trigger bucket reaches the queue through an S3 notification and the
    Lambda event source mapping writes its key to the result bucket; each deleted resource then
    answers its read and write calls with AWS's exact not-found code and message."""
    trigger_bucket = _create_bucket(ctx)
    queue = _create_queue(ctx)
    result_bucket = _create_bucket(ctx)

    # Set SQS policy for S3 to send messages
    sqs = ctx.client("sqs")
    queue_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue["arn"],
                    "Condition": {"ArnLike": {"aws:SourceArn": trigger_bucket["arn"]}},
                }
            ],
        }
    )
    sqs.set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={"Policy": queue_policy},
    )

    # Configure S3 notification -> SQS
    s3 = ctx.client("s3")
    s3.put_bucket_notification_configuration(
        Bucket=trigger_bucket["name"],
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "QueueArn": queue["arn"],
                    "Events": ["s3:ObjectCreated:*"],
                }
            ]
        },
    )

    handler_code = """
import boto3, os, json
def lambda_handler(event, context):
    s3 = boto3.client('s3')
    for record in event['Records']:
        body = json.loads(record['body'])
        for s3_record in body.get('Records', []):
            key = s3_record['s3']['object']['key']
            s3.put_object(
                Bucket=os.environ['RESULT_BUCKET'],
                Key='processed/' + key,
                Body=key.encode()
            )
    return {'ok': True}
"""
    fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        permissions=[
            {
                "Action": [
                    "sqs:ReceiveMessage",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes",
                ],
                "Resource": queue["arn"],
            },
            {"Action": ["s3:PutObject"], "Resource": result_bucket["arn"] + "/*"},
        ],
        env={"RESULT_BUCKET": result_bucket["name"]},
    )
    esm_uuid = _wire_event_source(ctx, fn["name"], queue["arn"], batch_size=1)

    # Drain S3 test event sent when the notification config was applied
    _drain_s3_test_events(ctx.client("sqs"), queue["url"])

    source_key = f"input/{ctx.unique_name('pipeline-')}.txt"
    s3.put_object(Bucket=trigger_bucket["name"], Key=source_key, Body=b"trigger")

    def _check_result():
        try:
            resp = s3.get_object(
                Bucket=result_bucket["name"], Key=f"processed/{source_key}"
            )
            return resp["Body"].read()
        except Exception:
            return None

    body = _poll_until(
        probe=_check_result,
        predicate=lambda x: x is not None,
        timeout_s=90,
        interval_s=5,
    )
    assert body == source_key.encode(), (
        f"expected Lambda to write the source key {source_key!r} as the object body, got {body!r}"
    )
    # Tear down in reverse dependency order and prove each resource gone.
    _gone_esm(ctx, esm_uuid, queue["arn"])
    _gone_lambda(ctx, fn["name"])
    _gone_role(ctx, fn["role"], "/sim2real/")
    _gone_bucket(ctx, trigger_bucket["name"])
    _gone_queue(ctx, queue["name"], queue["url"])
    _gone_bucket(ctx, result_bucket["name"])


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    # IAM role trust/permission propagation is bounded by _create_function_with_retry's
    # own retry loop (catches "cannot be assumed" for up to 30s), not an unconditional sleep here.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """S3 buckets must be emptied before deletion, or DeleteBucket fails with BucketNotEmpty:
    purge objects AND all versions/delete-markers (versioning may be on), then delete."""
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        targets = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if targets:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": targets})
    s3.delete_bucket(Bucket=bucket)


def _wait_function_active(ctx, name: str, timeout_s: float = 60) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
) -> dict[str, str]:
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.
    Registers the function's teardown (LIFO-before its role, since the role was registered first)."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    # Normalize inline handler source: dedent (checks often embed indented triple-quoted code) and
    # bind to the fixed entrypoint — the Handler is "lambda_function.lambda_handler", but inline code
    # is conventionally written as `def handler(event, context)`. Without a lambda_handler symbol the
    # function fails at runtime with Runtime.HandlerNotFound before any behavior is exercised. Both are
    # no-ops for code that's already column-0 and defines lambda_handler.
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs: dict[str, Any] = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(_tolerant(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
            # The function creates /aws/lambda/<name> on its first invoke and the group outlives the
            # function, so delete it too (a never-created group is tolerated as
            # ResourceNotFoundException).
            ctx.on_cleanup(
                _tolerant(
                    lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}"),
                    "ResourceNotFoundException",
                )
            )
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
) -> dict[str, str]:
    """Create a Lambda with an execution role scoped to `permissions` (a list of IAM statement
    fragments like [{"Action": ["sqs:SendMessage"], "Resource": queue_arn}]); logs are always
    allowed. Role + function each register their own teardown (function torn down first, LIFO).
    Returns {name,arn}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    fn = _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )
    return {**fn, "role": role["name"]}


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=url), *_SQS_NF))
    return {"name": name, "url": url, "arn": arn}


def _create_bucket(ctx) -> dict[str, str]:
    """Create an S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is CreateBucket's own no-LocationConstraint special case, not a region pin —
    # ctx.region still drives where the bucket actually lands.
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(_tolerant(lambda: _empty_and_delete_bucket(ctx, name), "NoSuchBucket"))
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    except ClientError:
        pass
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _wire_event_source(
    ctx,
    function_name,
    source_arn,
    batch_size=10,
    starting_position=None,
    extra_config=None,
) -> str:
    """Create an event-source mapping (SQS/DynamoDB Streams/Kinesis/...) and wait until Enabled
    (registers delete_event_source_mapping teardown). Returns the ESM UUID."""
    lam = ctx.client("lambda")
    params: dict[str, Any] = {
        "FunctionName": function_name,
        "EventSourceArn": source_arn,
        "BatchSize": batch_size,
        "Enabled": True,
    }
    if starting_position:
        params["StartingPosition"] = starting_position
    elif any(
        s in source_arn
        for s in [":stream/", "/stream/", ":kinesis:", ":kafka:", ":documentdb:"]
    ):
        params["StartingPosition"] = "LATEST"
    if extra_config:
        params.update(extra_config)
    esm_uuid = lam.create_event_source_mapping(**params)["UUID"]
    ctx.on_cleanup(_tolerant(lambda: lam.delete_event_source_mapping(UUID=esm_uuid), "ResourceNotFoundException"))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid).get("State"),
        lambda s: s == "Enabled",
        timeout_s=90,
        interval_s=3.0,
        description=f"ESM {esm_uuid} Enabled",
    )
    return esm_uuid


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status`` and exactly ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message {msg[:200]!r} != {message!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
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
                _refused(fn, codes, status, what, message)
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


def _gone_esm(ctx, uuid: str, source_arn: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_event_source_mapping(UUID=uuid)
    nf = ("ResourceNotFoundException",)
    gone = "The resource you requested does not exist."
    _poll_refused(lambda: lam.get_event_source_mapping(UUID=uuid), nf, 404, f"GetEventSourceMapping {uuid}", gone)
    listed = {m["UUID"] for m in _paged(lam, "list_event_source_mappings", "EventSourceMappings", EventSourceArn=source_arn)}
    assert uuid not in listed, f"ListEventSourceMappings still lists deleted mapping {uuid}"
    _refused(
        lambda: lam.update_event_source_mapping(UUID=uuid, BatchSize=1),
        nf, 404, f"UpdateEventSourceMapping {uuid}", gone,
    )


def _gone_lambda(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    arn = lam.get_function(FunctionName=name)["Configuration"]["FunctionArn"]
    lam.delete_function(FunctionName=name)
    nf = ("ResourceNotFoundException",)
    gone = f"Function not found: {arn}"
    _poll_refused(lambda: lam.get_function(FunctionName=name), nf, 404, f"GetFunction {name}", gone)
    listed = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
    assert name not in listed, f"ListFunctions still lists deleted function {name}"
    _refused(lambda: lam.invoke(FunctionName=name, Payload=b"{}"), nf, 404, f"Invoke {name}", f"{gone}:$LATEST")


def _gone_role(ctx, name: str, path: str = "/") -> None:
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    gone = f"The role with name {name} cannot be found."
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}", gone)
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=path)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}", gone,
    )


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # AWS documents up to 60 s for a deleted queue to stop answering.
    gone = "The specified queue does not exist."
    _poll_refused(lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}", gone)
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {name}", gone)


def _empty_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})


def _gone_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    _empty_bucket(s3, bucket)
    s3.delete_bucket(Bucket=bucket)
    # HeadBucket has no body: the code is the bare status and the message its reason phrase.
    _poll_refused(
        lambda: s3.head_bucket(Bucket=bucket),
        ("404", "NoSuchBucket", "NotFound"), 404, f"HeadBucket {bucket}", "Not Found",
    )
    names = {b["Name"] for b in s3.list_buckets(Prefix=bucket).get("Buckets", [])}
    assert bucket not in names, f"ListBuckets still lists deleted bucket {bucket}"
    _refused(
        lambda: s3.put_object(Bucket=bucket, Key="gone", Body=b"x"), ("NoSuchBucket",), 404, f"PutObject {bucket}",
        "The specified bucket does not exist",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
