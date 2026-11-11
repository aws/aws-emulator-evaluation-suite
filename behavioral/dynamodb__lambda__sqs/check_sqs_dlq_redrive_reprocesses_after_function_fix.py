"""sqs-dlq-redrive-reprocesses-after-function-fix."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-dlq-redrive-reprocesses-after-function-fix"

GROUP = "error-propagation"

SERVICES = ["dynamodb", "lambda", "sqs"]


# timing:real-time — visibility: 6 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A poison message lands on the DLQ, and StartMessageMoveTask reaches COMPLETED with a non-zero
    moved count, drains the DLQ, and lets the repaired consumer reprocess it; an ESM on a queue whose
    VisibilityTimeout is below the function Timeout is refused.
    """
    ddb = ctx.client("dynamodb")
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")

    dlq = _create_queue(ctx)
    # VisibilityTimeout 6 + maxReceiveCount 1 gets the poison message to the DLQ in seconds; it must
    # also be >= the function Timeout (5s), which Lambda enforces at CreateEventSourceMapping.
    main = _create_queue(
        ctx,
        VisibilityTimeout="6",
        RedrivePolicy=json.dumps(
            {"deadLetterTargetArn": dlq["arn"], "maxReceiveCount": 1}
        ),
    )

    control = _create_table(ctx)
    ddb.put_item(TableName=control["name"], Item={"pk": {"S": "mode"}, "v": {"S": "broken"}})

    # The consumer reads its mode from DynamoDB on every invoke, so the "fix the bug and redrive"
    # operator workflow is reproduced without a code update racing the ESM.
    code = """
    import json, os
    import boto3
    ddb = boto3.client("dynamodb")
    CONTROL = os.environ["CONTROL_TABLE"]

    def handler(event, context):
        mode = ddb.get_item(TableName=CONTROL, Key={"pk": {"S": "mode"}})["Item"]["v"]["S"]
        for record in event.get("Records", []):
            marker = json.loads(record["body"])["marker"]
            if mode == "broken":
                raise RuntimeError("consumer bug on " + marker)
            ddb.put_item(
                TableName=CONTROL,
                Item={"pk": {"S": "processed:" + marker}, "v": {"S": "ok"}},
            )
        return {"ok": True}
    """
    fn = _create_lambda(
        ctx,
        code,
        permissions=[
            {
                "Action": [
                    "sqs:ReceiveMessage",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes",
                ],
                "Resource": main["arn"],
            },
            {"Action": ["dynamodb:GetItem", "dynamodb:PutItem"], "Resource": control["arn"]},
        ],
        env={"CONTROL_TABLE": control["name"]},
        timeout=5,
    )

    # A source queue whose VisibilityTimeout is below the function Timeout cannot be wired,
    # because a redelivery could race an invocation that is still running.
    sqs.set_queue_attributes(QueueUrl=main["url"], Attributes={"VisibilityTimeout": "2"})
    _wait_for_effect(
        lambda: sqs.get_queue_attributes(
            QueueUrl=main["url"], AttributeNames=["VisibilityTimeout"]
        )["Attributes"]["VisibilityTimeout"],
        lambda v: v == "2",
        timeout_s=60,
        interval_s=2.0,
        description="the shortened VisibilityTimeout is readable",
    )
    try:
        lam.create_event_source_mapping(
            FunctionName=fn["name"], EventSourceArn=main["arn"], BatchSize=1, Enabled=True
        )
        raise AssertionError(
            "an ESM on a queue whose VisibilityTimeout (2s) is below the function Timeout (5s) "
            "must be refused"
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == "InvalidParameterValueException", (
            f"expected InvalidParameterValueException, got {err.get('Code')}: "
            f"{err.get('Message')!r}"
        )
        assert err.get("Message") == (
            "Queue visibility timeout: 2 seconds is less than Function timeout: 5 seconds"
        ), f"the refusal must quote both timeouts, got {err.get('Message')!r}"
    assert (
        lam.list_event_source_mappings(
            FunctionName=fn["name"], EventSourceArn=main["arn"]
        ).get("EventSourceMappings", [])
        == []
    ), "the refused CreateEventSourceMapping must leave no mapping behind"

    # SQS attribute changes take up to 60s to be seen by other services, hence the retry window.
    sqs.set_queue_attributes(QueueUrl=main["url"], Attributes={"VisibilityTimeout": "6"})
    _wait_for_effect(
        lambda: sqs.get_queue_attributes(
            QueueUrl=main["url"], AttributeNames=["VisibilityTimeout"]
        )["Attributes"]["VisibilityTimeout"],
        lambda v: v == "6",
        timeout_s=60,
        interval_s=2.0,
        description="the restored VisibilityTimeout is readable",
    )
    _retry_until_accepted(
        lambda: _wire_event_source(ctx, fn["name"], main["arn"], batch_size=1),
        codes={"InvalidParameterValueException"},
        timeout_s=120,
        interval_s=5.0,
        description="CreateEventSourceMapping accepted once the VisibilityTimeout propagates",
    )

    marker = _xname(ctx, "poison")
    sqs.send_message(QueueUrl=main["url"], MessageBody=json.dumps({"marker": marker}))

    # 180s: ESM enable + cold start + the failing receive + the visibility timeout before the DLQ move.
    def _dlq_depth():
        attrs = sqs.get_queue_attributes(
            QueueUrl=dlq["url"],
            AttributeNames=["ApproximateNumberOfMessages"],
        )["Attributes"]
        return int(attrs["ApproximateNumberOfMessages"])

    # The move task sizes itself from the DLQ's approximate count when it starts, so the count must
    # read >= 1 on three successive polls first; a single read can lead what the task sees.
    streak = {"n": 0}

    def _settled(n):
        streak["n"] = streak["n"] + 1 if n >= 1 else 0
        return streak["n"] >= 3

    _wait_for_effect(
        _dlq_depth,
        _settled,
        timeout_s=200,
        interval_s=5.0,
        description="poison message settled on the DLQ",
    )

    assert (
        "Item"
        not in ddb.get_item(
            TableName=control["name"], Key={"pk": {"S": f"processed:{marker}"}}
        )
    ), f"the broken consumer must not have recorded {marker} as processed"

    ddb.put_item(TableName=control["name"], Item={"pk": {"S": "mode"}, "v": {"S": "fixed"}})

    task_handle = sqs.start_message_move_task(SourceArn=dlq["arn"])["TaskHandle"]
    assert task_handle, "StartMessageMoveTask returned no TaskHandle"

    def _task():
        results = sqs.list_message_move_tasks(SourceArn=dlq["arn"]).get("Results", [])
        return results[0] if results else None

    # 120s: the move task is asynchronous; SQS reports RUNNING then COMPLETED.
    task = _wait_for_effect(
        _task,
        lambda t: t is not None and t.get("Status") in ("COMPLETED", "FAILED", "CANCELLED"),
        timeout_s=120,
        interval_s=5.0,
        description="message move task terminal status",
    )
    assert task["Status"] == "COMPLETED", (
        f"message move task did not complete: {task!r}"
    )
    assert task.get("SourceArn") == dlq["arn"], (
        f"move task SourceArn wrong: {task.get('SourceArn')!r}"
    )
    # ApproximateNumberOfMessagesMoved lags the COMPLETED status by a few seconds; poll it separately.
    task = _wait_for_effect(
        _task,
        lambda t: t is not None and t.get("ApproximateNumberOfMessagesMoved", 0) > 0,
        timeout_s=90,
        interval_s=3.0,
        description="ApproximateNumberOfMessagesMoved counter to catch up to the COMPLETED task",
    )
    assert task.get("ApproximateNumberOfMessagesMoved", 0) >= 1, (
        f"move task reported COMPLETED but moved nothing: {task!r}"
    )

    # 180s: redelivery through the ESM after the move.
    _wait_for_effect(
        lambda: ddb.get_item(
            TableName=control["name"], Key={"pk": {"S": f"processed:{marker}"}}
        ).get("Item"),
        lambda i: i is not None,
        timeout_s=180,
        interval_s=5.0,
        description=f"redriven message {marker} reprocessed",
    )

    _wait_for_effect(
        _dlq_depth,
        lambda n: n == 0,
        timeout_s=120,
        interval_s=5.0,
        description="DLQ drained by the move task",
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _retry_until_accepted(fn, *, codes, timeout_s, interval_s, description):
    """Call fn() until it succeeds; retry only a ClientError whose code is in `codes`, and raise
    AssertionError when the deadline passes or any other error is raised."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in codes:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} not met within {timeout_s}s; last {code}: "
                    f"{exc.response.get('Error', {}).get('Message')!r}"
                ) from exc
        time.sleep(interval_s)


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; raise on timeout."""
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


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect; ESM cold start + first delivery can take 60-120s."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its teardown. Returns {name,arn}."""
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
    # Role propagation is absorbed by _create_function_with_retry's bounded retry.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _drop_log_group(ctx, fn_name: str) -> None:
    """Delete a Lambda's auto-created log group, tolerating its never having been created."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


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
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
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
            # The auto-created log group survives function deletion; registered first so it is
            # deleted after the function, which could otherwise recreate it.
            ctx.on_cleanup(lambda: _drop_log_group(ctx, name))
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
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
    """Create a Lambda whose execution role allows `permissions` (IAM statement fragments) plus logs.
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
    return _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )


def _create_table(
    ctx,
    key_schema=None,
    attributes=None,
    stream=False,
    stream_view_type="NEW_AND_OLD_IMAGES",
) -> dict[str, str]:
    """Create a DynamoDB table (PAY_PER_REQUEST; waits table_exists; registers delete_table).
    Returns {name,arn[,stream_arn]}."""
    name = _xname(ctx, "tbl")
    ddb = ctx.client("dynamodb")
    params: dict[str, Any] = {
        "TableName": name,
        "KeySchema": key_schema or [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": attributes
        or [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
        "Tags": _xsvc_tags_kv(),
    }
    if stream:
        params["StreamSpecification"] = {
            "StreamEnabled": True,
            "StreamViewType": stream_view_type,
        }
    resp = ddb.create_table(**params)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(
        TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 30}
    )
    result = {"name": name, "arn": resp["TableDescription"]["TableArn"]}
    if stream:
        result["stream_arn"] = resp["TableDescription"].get("LatestStreamArn", "")
    return result


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
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


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
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=esm_uuid))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid).get("State"),
        lambda s: s == "Enabled",
        timeout_s=90,
        interval_s=3.0,
        description=f"ESM {esm_uuid} Enabled",
    )
    return esm_uuid


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
