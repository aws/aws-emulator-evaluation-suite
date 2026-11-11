"""s3-eventbridge-sfn-lambda-ddb-payload-fidelity."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-eventbridge-sfn-lambda-ddb-payload-fidelity"

GROUP = "data-format"

SERVICES = ["dynamodb", "events", "lambda", "s3", "stepfunctions"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A native S3 Object Created event survives S3 -> EventBridge -> Step Functions -> Lambda ->
    DynamoDB field by field, so a target that re-wraps, flattens or drops ``detail`` on the way
    into the Lambda event fails even though the execution SUCCEEDS."""
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")
    events = ctx.client("events")
    account = _account_id(ctx)

    table = _create_table(ctx)
    bucket = _create_bucket(ctx)
    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"],
        NotificationConfiguration={"EventBridgeConfiguration": {}},
    )

    # The handler stores the event VERBATIM so the check can assert on the whole envelope
    # instead of on whatever subset the handler happened to look at.
    code = """
    import json, os
    import boto3
    ddb = boto3.client("dynamodb")
    TABLE = os.environ["TABLE"]

    def handler(event, context):
        key = event.get("detail", {}).get("object", {}).get("key", "MISSING")
        ddb.put_item(TableName=TABLE, Item={
            "pk": {"S": key},
            "envelope": {"S": json.dumps(event)},
        })
        return {"ok": True}
    """
    fn = _create_lambda(
        ctx,
        code,
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": table["arn"]}],
        env={"TABLE": table["name"]},
    )

    # "Payload.$": "$" hands the state machine's whole input (the EventBridge envelope) to the
    # function unchanged, so any mangling is the emulator's, not the definition's.
    sm = _create_state_machine(
        ctx,
        definition={
            "StartAt": "InvokeHandler",
            "States": {
                "InvokeHandler": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {
                        "FunctionName": fn["arn"],
                        "Payload.$": "$",
                    },
                    "End": True,
                }
            },
        },
        permissions=[
            {"Action": ["lambda:InvokeFunction"], "Resource": [fn["arn"], fn["arn"] + ":*"]}
        ],
    )

    rule_name = _xname(ctx, "rule")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {
                "source": ["aws.s3"],
                "detail-type": ["Object Created"],
                "detail": {"bucket": {"name": [bucket["name"]]}},
            }
        ),
        State="ENABLED",
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))
    events_role = _create_role(
        ctx,
        "events.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "states:StartExecution",
                    "Resource": sm["arn"],
                }
            ],
        },
    )
    events.put_targets(
        Rule=rule_name,
        Targets=[{"Id": "sfn-target", "Arn": sm["arn"], "RoleArn": events_role["arn"]}],
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["sfn-target"])
    )

    body = b"payload-fidelity-across-four-hops"
    object_key = "fidelity/probe-object.txt"

    def _upload_and_probe():
        # Re-upload on each poll: an S3 -> EventBridge event raised before the rule/target is live
        # is dropped, and re-writing the same key is idempotent because the handler keys the sink
        # item on the object key.
        s3.put_object(Bucket=bucket["name"], Key=object_key, Body=body)
        return ddb.get_item(
            TableName=table["name"], Key={"pk": {"S": object_key}}
        ).get("Item")

    # 300s: four hops, each with its own propagation window (S3 notification config, rule
    # target, SFN start, Lambda cold start). This is the longest chain.
    item = _wait_for_effect(
        _upload_and_probe,
        lambda i: i is not None,
        timeout_s=300,
        interval_s=10.0,
        description="S3 -> EventBridge -> SFN -> Lambda -> DynamoDB delivery",
    )

    envelope = json.loads(item["envelope"]["S"])

    # --- envelope-level fields must survive the SFN hop --------------------------------
    for field in ("version", "id", "detail-type", "source", "account", "time", "region",
                  "resources", "detail"):
        assert field in envelope, (
            f"EventBridge envelope field {field!r} lost between EventBridge and Lambda; "
            f"got keys {sorted(envelope)}"
        )
    assert envelope["source"] == "aws.s3", f"source rewritten: {envelope['source']!r}"
    assert envelope["detail-type"] == "Object Created", (
        f"detail-type rewritten: {envelope['detail-type']!r}"
    )
    assert envelope["account"] == account, (
        f"account rewritten: {envelope['account']!r} != {account}"
    )
    assert envelope["region"] == ctx.region, (
        f"region rewritten: {envelope['region']!r} != {ctx.region}"
    )
    assert bucket["arn"] in envelope["resources"], (
        f"S3 event must carry the bucket ARN in resources, got {envelope['resources']}"
    )

    # --- nested detail must survive intact, not be flattened or truncated --------------
    detail = envelope["detail"]
    assert detail.get("bucket", {}).get("name") == bucket["name"], (
        f"detail.bucket.name mangled: {detail.get('bucket')!r}"
    )
    assert detail.get("object", {}).get("key") == object_key, (
        f"detail.object.key mangled: {detail.get('object')!r}"
    )
    assert detail.get("object", {}).get("size") == len(body), (
        f"detail.object.size wrong: {detail.get('object', {}).get('size')!r} != {len(body)}"
    )
    assert detail.get("object", {}).get("etag"), (
        f"detail.object.etag missing from the delivered S3 event: {detail.get('object')!r}"
    )
    assert detail.get("reason") == "PutObject", (
        f"detail.reason wrong: {detail.get('reason')!r} != 'PutObject'"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xsvc_tags_lower() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _xsvc_resource_tags().items()]


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


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


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
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The function creates /aws/lambda/<name> on first invoke and that log group outlives
            # the function, so delete it too.
            ctx.on_cleanup(
                lambda: ctx.client("logs").delete_log_group(
                    logGroupName=f"/aws/lambda/{name}"
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


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Delete every object under a bucket, then the bucket (S3 refuses a non-empty delete)."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _create_bucket(ctx) -> dict[str, str]:
    """Create an S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's region-less default; it rejects an explicit
        # LocationConstraint naming itself, so this is a region-pinned S3 API quirk,
        # not a hardcoded assumption about where the check runs.
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    except ClientError:
        pass
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _create_state_machine(ctx, definition, permissions=None) -> dict[str, str]:
    """Create a Step Functions state machine with an execution role (permissions=None → full
    access; [] → empty policy, for denial tests). Role + SM register their own teardown.
    Returns {name,arn}."""
    if permissions is None:
        statements = [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    elif permissions:
        statements = [
            {"Effect": "Allow", "Action": p["Action"], "Resource": p["Resource"]}
            for p in permissions
        ]
    else:
        statements = []
    policy = {"Version": "2012-10-17", "Statement": statements} if statements else None
    role = _create_role(ctx, "states.amazonaws.com", inline_policy=policy)
    name = _xname(ctx, "sm")
    sfn = ctx.client("stepfunctions")
    # The role's trust policy needs to propagate before SFN can assume it; retry through
    # that window instead of sleeping unconditionally before we know it's needed.
    deadline = time.monotonic() + 30
    last_err = None
    arn = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role["arn"],
                type="STANDARD",
                tags=_xsvc_tags_lower(),
            )["stateMachineArn"]
            break
        except ClientError as e:
            if "AccessDeniedException" in str(e) or "is not authorized" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    if arn is None:
        raise last_err or RuntimeError(f"Failed to create state machine {name}")
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    ctx.on_cleanup(lambda: _stop_and_delete_state_machine(ctx, arn))
    return {"name": name, "arn": arn}


def _stop_and_delete_state_machine(ctx, arn: str) -> None:
    """Delete a Step Functions state machine and wait until it is gone.

    SFN deletion is asynchronous, and a state machine with a RUNNING execution lingers in
    DELETING, so running executions are stopped first. A state machine or execution already gone
    is fine; any other error, or the state machine still present after 90 s, raises.
    """
    sfn = ctx.client("stepfunctions")
    try:
        paginator = sfn.get_paginator("list_executions")
        for page in paginator.paginate(stateMachineArn=arn, statusFilter="RUNNING"):
            for ex in page.get("executions", []):
                try:
                    sfn.stop_execution(executionArn=ex["executionArn"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
                        raise
        sfn.delete_state_machine(stateMachineArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
            raise
        return
    deadline = time.monotonic() + 90
    while True:
        try:
            sfn.describe_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                raise
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"state machine {arn} still present 90 s after DeleteStateMachine")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
