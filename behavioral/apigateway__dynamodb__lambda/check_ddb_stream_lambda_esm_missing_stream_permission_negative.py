"""ddb-stream-lambda-esm-missing-stream-permission-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddb-stream-lambda-esm-missing-stream-permission-negative"

GROUP = "overly-permissive"

SERVICES = ["apigateway", "dynamodb", "lambda"]

BOOTSTRAP_DDB_CODE = """
import json, os, boto3
def lambda_handler(event, context):
    ddb = boto3.client("dynamodb", region_name=os.environ["AWS_REGION"])
    table_name = event["table_name"]
    key_schema = event["key_schema"]
    attributes = event["attributes"]
    stream = event.get("stream", False)

    kwargs = dict(
        TableName=table_name,
        KeySchema=key_schema,
        AttributeDefinitions=attributes,
        BillingMode="PAY_PER_REQUEST",
    )
    if stream:
        kwargs["StreamSpecification"] = {
            "StreamEnabled": True,
            "StreamViewType": "NEW_AND_OLD_IMAGES",
        }
    try:
        resp = ddb.create_table(**kwargs)
    except Exception as e:
        if "ResourceInUse" not in str(e):
            raise

    # Use boto3 waiter to poll for ACTIVE (no sleep)
    waiter = ddb.get_waiter("table_exists")
    waiter.wait(TableName=table_name, WaiterConfig={"MaxAttempts": 60, "Delay": 2})

    table = ddb.describe_table(TableName=table_name)["Table"]
    result = {"name": table["TableName"], "arn": table["TableArn"]}
    if stream and "LatestStreamArn" in table:
        result["stream_arn"] = table["LatestStreamArn"]
    return {"statusCode": 200, "body": json.dumps(result)}
"""

BOOTSTRAP_DDB_PERMISSIONS = [
    {
        "Action": [
            "dynamodb:CreateTable",
            "dynamodb:DescribeTable",
            "dynamodb:PutItem",
            "dynamodb:GetItem",
            "dynamodb:DeleteItem",
            "dynamodb:UpdateTable",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:GetRecords",
            "dynamodb:GetShardIterator",
            "dynamodb:DescribeStream",
            "dynamodb:ListStreams",
            "dynamodb:TransactWriteItems",
        ],
        "Resource": "*",
    },
    {
        "Action": [
            "apigateway:GET",
            "apigateway:POST",
            "apigateway:PUT",
            "apigateway:DELETE",
            "apigateway:PATCH",
        ],
        "Resource": "*",
    },
    # The setup Lambda grants API Gateway the right to invoke the handler Lambda
    # (lambda.add_permission). Without lambda:AddPermission on the setup role that
    # call is AccessDenied and the whole proxy wiring fails — so every positive
    # APIGW proxy check errored at setup. Grant the resource-policy mutation verbs.
    {
        "Action": [
            "lambda:AddPermission",
            "lambda:RemovePermission",
            "lambda:GetPolicy",
        ],
        "Resource": "*",
    },
]


def _create_table_via_lambda(
    ctx,
    bootstrap_fn: dict,
    table_name: str,
    key_schema: list,
    attributes: list,
    stream: bool = False,
) -> dict:
    """Create DynamoDB table by invoking the bootstrap Lambda. Returns {name, arn, stream_arn?}."""
    result = _invoke_lambda(
        ctx,
        bootstrap_fn["name"],
        {
            "table_name": table_name,
            "key_schema": key_schema,
            "attributes": attributes,
            "stream": stream,
        },
    )
    payload = (
        result["payload"]
        if isinstance(result["payload"], dict)
        else json.loads(result["payload"])
    )
    if result.get("error"):
        raise RuntimeError(f"Bootstrap Lambda error: {result}")
    body = payload.get("body", "{}")
    if isinstance(body, str):
        body = json.loads(body)
    # The table is created inside the bootstrap Lambda, so register its deletion here.
    ctx.on_cleanup(lambda: ctx.client("dynamodb").delete_table(TableName=table_name))
    return body


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventSourceMapping refuses a function whose role lacks DynamoDB Streams read permissions
    with InvalidParameterValueException and the exact stream-access message, while a mapping on the
    same stream with those permissions reaches Enabled."""
    bootstrap_fn = _create_lambda(
        ctx,
        handler_code=BOOTSTRAP_DDB_CODE,
        permissions=BOOTSTRAP_DDB_PERMISSIONS,
    )
    table_name = ctx.unique_name("tbl")
    table = _create_table_via_lambda(
        ctx,
        bootstrap_fn,
        table_name,
        key_schema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        attributes=[{"AttributeName": "pk", "AttributeType": "S"}],
        stream=True,
    )
    stream_arn = table.get("stream_arn")
    assert stream_arn, f"Table stream ARN missing: {table}"

    lam = ctx.client("lambda")

    # ---- positive control: identical stream, a role WITH stream-read permissions ----
    good_fn = _create_lambda(
        ctx,
        handler_code="def lambda_handler(e, c): return {'statusCode': 200}",
        permissions=[
            {
                "Action": [
                    "dynamodb:GetRecords",
                    "dynamodb:GetShardIterator",
                    "dynamodb:DescribeStream",
                    "dynamodb:ListStreams",
                ],
                "Resource": stream_arn,
            }
        ],
    )
    good_resp = _create_esm_once_role_propagates(lam, stream_arn, good_fn["name"])
    good_uuid = good_resp["UUID"]
    ctx.on_cleanup(
        lambda: ctx.client("lambda").delete_event_source_mapping(UUID=good_uuid)
    )
    good_state = _wait_for_effect(
        lambda: lam.get_event_source_mapping(UUID=good_uuid)["State"],
        lambda s: s in ("Enabled", "Problem", "Failed"),
    )
    assert good_state == "Enabled", (
        f"positive control: an ESM with correct stream-read permissions on the same table "
        f"never reached Enabled, got {good_state!r} -- the account has no working ESM "
        f"delivery path here, so the negative below would prove nothing"
    )

    # ---- break exactly one thing: the same wiring with NO stream permissions ----
    fn = _create_lambda(
        ctx,
        handler_code="def lambda_handler(e, c): return {'statusCode': 200}",
        permissions=[],  # NO stream permissions
    )

    code, message = _esm_refusal(
        ctx,
        lambda: lam.create_event_source_mapping(
            EventSourceArn=stream_arn,
            FunctionName=fn["name"],
            StartingPosition="TRIM_HORIZON",
            BatchSize=1,
        ),
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for a role that cannot read the stream, "
        f"got {code!r}: {message!r}"
    )
    assert message == (
        f"Cannot access stream {stream_arn}. Please ensure the role can perform the "
        f"GetRecords, GetShardIterator, DescribeStream, and ListStreams Actions on your "
        f"stream in IAM."
    ), f"unexpected stream-access refusal message {message!r}"


def _esm_refusal(ctx, fn):
    """(code, message) of the ClientError CreateEventSourceMapping raises. An accepted mapping is
    registered for teardown and fails the check: the positive control shows the identical stream
    is deliverable, so acceptance means the missing stream permissions were not enforced."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    esm_uuid = resp["UUID"]
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_event_source_mapping(UUID=esm_uuid))
    raise AssertionError(
        f"CreateEventSourceMapping accepted a role with no stream-read permissions "
        f"(ESM {esm_uuid}, state {resp.get('State')!r}); the positive control above shows "
        f"the identical stream is deliverable"
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


def _create_esm_once_role_propagates(lam, stream_arn: str, fn_name: str, timeout_s=90.0):
    """CreateEventSourceMapping, retried while the function role's fresh grant propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_event_source_mapping(
                EventSourceArn=stream_arn,
                FunctionName=fn_name,
                StartingPosition="TRIM_HORIZON",
                BatchSize=1,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InvalidParameterValueException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


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
    # Dedent the inline source and alias `handler` to `lambda_handler`, the fixed entrypoint;
    # without that symbol the function fails with Runtime.HandlerNotFound.
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
            # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
            # function deletion, so delete it
            # too; a function that never logged has no group to delete.
            ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{name}"))
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


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


def _invoke_lambda(ctx, name: str, payload: dict | None = None) -> dict[str, Any]:
    """Invoke a Lambda synchronously; return {status_code[, error], payload|payload_raw}."""
    resp = ctx.client("lambda").invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode(),
    )
    body = resp["Payload"].read()
    result: dict[str, Any] = {"status_code": resp["StatusCode"]}
    if resp.get("FunctionError"):
        result["error"] = resp["FunctionError"]
    try:
        result["payload"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        result["payload_raw"] = body.decode("utf-8", errors="replace")
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
