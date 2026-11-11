"""sfn-saga-compensate-on-failure."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-saga-compensate-on-failure"

GROUP = "saga"

SERVICES = ["dynamodb", "lambda", "stepfunctions"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """SFN saga: step 1 succeeds (DDB write), step 2 fails (Lambda error), compensation runs."""
    table = _create_table(ctx)
    ddb = ctx.client("dynamodb")

    fail_fn = _create_lambda(
        ctx,
        handler_code="def lambda_handler(event, context): raise Exception('ChargeDeclined')\n",
    )

    compensate_fn = _create_lambda(
        ctx,
        handler_code=(
            "import boto3, json, os\n"
            "def lambda_handler(event, context):\n"
            "    ddb = boto3.client('dynamodb', endpoint_url=os.environ.get('AWS_ENDPOINT_URL'))\n"
            "    ddb.put_item(TableName=os.environ['TABLE'], Item={\n"
            "        'pk': {'S': 'compensation-executed'},\n"
            "        'reason': {'S': json.dumps(event)[:200]},\n"
            "    })\n"
            "    return {'compensated': True}\n"
        ),
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": table["arn"]}],
        env={"TABLE": table["name"]},
    )

    sm = _create_state_machine(
        ctx,
        definition={
            "StartAt": "Step1_Reserve",
            "States": {
                "Step1_Reserve": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::dynamodb:putItem",
                    "Parameters": {
                        "TableName": table["name"],
                        "Item": {
                            "pk": {"S": "reservation"},
                            "status": {"S": "reserved"},
                        },
                    },
                    "Next": "Step2_Charge",
                },
                "Step2_Charge": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {
                        "FunctionName": fail_fn["arn"],
                        "Payload.$": "$",
                    },
                    "Catch": [
                        {
                            "ErrorEquals": ["States.ALL"],
                            "Next": "Compensate",
                            "ResultPath": "$.error",
                        }
                    ],
                    "End": True,
                },
                "Compensate": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {
                        "FunctionName": compensate_fn["arn"],
                        "Payload.$": "$.error",
                    },
                    "End": True,
                },
            },
        },
        permissions=[
            {"Action": ["dynamodb:PutItem"], "Resource": table["arn"]},
            {
                "Action": ["lambda:InvokeFunction"],
                "Resource": [fail_fn["arn"], compensate_fn["arn"]],
            },
        ],
    )
    ctx.on_cleanup(lambda: _stop_and_delete_state_machine(ctx, sm["arn"]))

    sfn = ctx.client("stepfunctions")

    # A fresh role's grants take 15-30 s to propagate; until then a step fails with an
    # authorization error and the execution ends FAILED, so a FAILED run is retried to a deadline.
    left = ctx.time_left()
    deadline = time.monotonic() + (375 if left is None else min(375, left))
    while True:
        execution = sfn.start_execution(stateMachineArn=sm["arn"], input=json.dumps({}))
        exec_arn = execution["executionArn"]
        desc = _wait_for_effect(
            lambda: sfn.describe_execution(executionArn=exec_arn),
            lambda d: d["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=60,
        )
        if desc["status"] == "SUCCEEDED" or time.monotonic() >= deadline:
            break
        time.sleep(2)

    assert desc["status"] == "SUCCEEDED", (
        "Saga should succeed (via compensation path), got "
        f"{desc['status']} error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )

    comp_item = ddb.get_item(
        TableName=table["name"], Key={"pk": {"S": "compensation-executed"}}
    ).get("Item")
    assert comp_item is not None, "Compensation Lambda was not invoked"


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _stop_and_delete_state_machine(ctx, arn: str) -> None:
    """Delete a Step Functions state machine synchronously.

    A plain ``delete_state_machine`` fires and moves on, but SFN deletion is
    asynchronous: the state machine lingers in DELETING (and stays visible to the
    account audit) — indefinitely if it still has a RUNNING execution (e.g. a
    waitForTaskToken task nobody resumed). Stop any running executions first, then
    wait until the state machine is actually gone. Registered via ``on_cleanup``
    AFTER the state machine is created so LIFO runs it BEFORE the plain
    delete_state_machine teardown that ``create_state_machine`` registered.
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
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
            raise
        return
    sfn.delete_state_machine(stateMachineArn=arn)
    deadline = time.monotonic() + 210
    while time.monotonic() < deadline:
        try:
            sfn.describe_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                raise
            return
        time.sleep(2)
    raise RuntimeError(f"state machine {arn} still exists 210 s after DeleteStateMachine")


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


def _delete_log_group(ctx, log_group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The function auto-creates /aws/lambda/<name> on first invoke and that log group
            # survives function deletion; a function never invoked has no log group to delete.
            ctx.on_cleanup(lambda: _delete_log_group(ctx, f"/aws/lambda/{name}"))
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
    # A just-created role is refused ("not authorized to assume the provided role") until IAM
    # propagates its trust policy; retry that one code on a bounded deadline.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role["arn"],
                type="STANDARD",
                tags=_xsvc_tags_lower(),
            )["stateMachineArn"]
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
        time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return {"name": name, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
