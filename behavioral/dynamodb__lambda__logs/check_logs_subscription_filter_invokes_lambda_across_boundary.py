"""logs-subscription-filter-invokes-lambda-across-boundary."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "logs-subscription-filter-invokes-lambda-across-boundary"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "lambda", "logs"]


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags():
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv():
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind):
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


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


def _err_code(fn):
    """Call fn(); return the botocore Error.Code if a ClientError is raised, else None."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _retry_client_error(fn, *, codes, timeout_s=120.0, interval_s=3.0, description="call"):
    """Call fn() until it stops raising one of `codes`, with a bounded deadline.

    IAM propagation is real and slow: a resource policy naming a just-created role is rejected
    ("invalid principal") until IAM converges, and a service that must assume a brand-new role
    reports it cannot. This retries that window to a deadline, never a bare time.sleep.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in codes or time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} still failing with {code} after {timeout_s}s"
                ) from exc
        time.sleep(interval_s)


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_role(ctx, trust, inline_policy=None, kind=None):
    """Create an IAM role and register its (policies-then-role) teardown. Returns {name, arn}.

    `trust` is either a service principal string ("lambda.amazonaws.com") or a full trust-policy
    document, for a role that another role assumes.
    """
    iam = ctx.client("iam")
    if isinstance(trust, str):
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": trust},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        kind = kind or f"role-{trust.split('.')[0]}"
    else:
        doc = trust
        kind = kind or "role"
    role_name = _xname(ctx, kind)
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(doc),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name):
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
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


def _wait_function_active(ctx, name, timeout_s=90.0):
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(ctx, handler_code, role_arn, env=None, timeout=30, memory=128,
                                runtime="python3.12"):
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.

    Registers the function + its auto-created log group for teardown. The inline handler source is
    dedented and aliased to the fixed `lambda_function.lambda_handler` entrypoint.
    """
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs = {
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
    deadline = time.monotonic() + 60
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
            ctx.on_cleanup(
                lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
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


def _create_lambda(ctx, handler_code, permissions=None, env=None, timeout=30, memory=128,
                   runtime="python3.12"):
    """Create a Lambda whose execution role is scoped to `permissions` (IAM statement fragments
    like [{"Action": ["kms:Decrypt"], "Resource": key_arn}]); logs are always allowed.

    Returns {name, arn, role_name, role_arn} — the role identifiers matter here because these
    checks name the execution role as the *principal* in another service's resource policy.
    """
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        resource = perm["Resource"] if isinstance(perm["Resource"], list) else [perm["Resource"]]
        stmt = {"Effect": perm.get("Effect", "Allow"), "Action": actions, "Resource": resource}
        if perm.get("Condition"):
            stmt["Condition"] = perm["Condition"]
        statements.append(stmt)
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    fn = _create_function_with_retry(ctx, handler_code, role["arn"], env, timeout, memory, runtime)
    return {**fn, "role_name": role["name"], "role_arn": role["arn"]}


def _invoke_lambda(ctx, name, payload=None):
    """Invoke a Lambda synchronously; return {status_code[, error], payload|payload_raw}."""
    resp = ctx.client("lambda").invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode(),
    )
    body = resp["Payload"].read()
    result = {"status_code": resp["StatusCode"]}
    if resp.get("FunctionError"):
        result["error"] = resp["FunctionError"]
    try:
        result["payload"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        result["payload_raw"] = body.decode("utf-8", errors="replace")
    return result


def _invoke_payload(ctx, name, payload=None):
    """Invoke and return the parsed RESULT PAYLOAD, asserting the handler did not fault.

    A 200 from Invoke proves nothing about the cross-service reference; the payload the handler
    produced after touching the other service is the evidence.
    """
    result = _invoke_lambda(ctx, name, payload)
    assert result.get("status_code") == 200, f"Invoke did not return 200: {result!r}"
    assert "error" not in result, f"handler faulted instead of returning a result: {result!r}"
    assert "payload" in result, f"handler returned non-JSON: {result!r}"
    return result["payload"]


def _create_table(ctx, kind="tbl"):
    """Create a PAY_PER_REQUEST table keyed by a single string `pk`; register teardown.
    Returns {name, arn}."""
    ddb = ctx.client("dynamodb")
    name = _xname(ctx, kind)
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ctx.client("dynamodb").delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return {"name": name, "arn": ddb.describe_table(TableName=name)["Table"]["TableArn"]}


def _get_item(ctx, table, pk):
    """GetItem with a TYPED key; returns the raw item dict or None."""
    return ctx.client("dynamodb").get_item(
        TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True
    ).get("Item")


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Logs subscription filter whose destination is a Lambda function (allowed by a policy scoped to the log
    group) records that function ARN and invokes it with the gzipped awslogs envelope: messageType DATA_MESSAGE
    and the source log group and stream.
    """
    logs = ctx.client("logs")
    lam = ctx.client("lambda")
    table = _create_table(ctx, "tbl-logs")
    group = _xname(ctx, "lg")
    logs.create_log_group(logGroupName=group, tags=dict(_xsvc_resource_tags()))
    ctx.on_cleanup(lambda: ctx.client("logs").delete_log_group(logGroupName=group))
    group_arn = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]["arn"]
    if not group_arn.endswith(":*"):
        group_arn = f"{group_arn}:*"

    code = """
        import base64
        import gzip
        import json
        import os

        import boto3

        ddb = boto3.client("dynamodb")


        def handler(event, context):
            raw = base64.b64decode(event["awslogs"]["data"])
            payload = json.loads(gzip.decompress(raw).decode())
            for entry in payload["logEvents"]:
                ddb.put_item(
                    TableName=os.environ["TABLE"],
                    Item={
                        "pk": {"S": entry["message"]},
                        "log_group": {"S": payload["logGroup"]},
                        "log_stream": {"S": payload["logStream"]},
                        "message_type": {"S": payload["messageType"]},
                    },
                )
            return {"count": len(payload["logEvents"])}
    """
    fn = _create_lambda(
        ctx,
        code,
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": table["arn"]}],
        env={"TABLE": table["name"]},
    )

    # The cross-boundary identity: Logs may invoke this function, but only for this log group.
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId="sim2real-xsvc-logs-invoke",
        Action="lambda:InvokeFunction",
        Principal=f"logs.{ctx.region}.amazonaws.com",
        SourceArn=group_arn,
    )
    ctx.on_cleanup(
        lambda: ctx.client("lambda").remove_permission(
            FunctionName=fn["name"], StatementId="sim2real-xsvc-logs-invoke"
        )
    )
    policy = json.loads(lam.get_policy(FunctionName=fn["name"])["Policy"])
    sids = [s["Sid"] for s in policy["Statement"]]
    assert "sim2real-xsvc-logs-invoke" in sids, (
        f"AddPermission must be visible in the function policy: {sids!r}"
    )

    filter_name = _xname(ctx, "subf")
    # Logs validates it can invoke the destination at PutSubscriptionFilter time, so this races the
    # function-policy propagation -- retry the documented failure code to a bounded deadline.
    _retry_client_error(
        lambda: logs.put_subscription_filter(
            logGroupName=group,
            filterName=filter_name,
            filterPattern="",
            destinationArn=fn["arn"],
        ),
        codes=("InvalidParameterException",),
        description="PutSubscriptionFilter against a just-permitted Lambda destination",
    )
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_subscription_filter(
            logGroupName=group, filterName=filter_name
        )
    )
    filters = logs.describe_subscription_filters(logGroupName=group)["subscriptionFilters"]
    assert [f["destinationArn"] for f in filters] == [fn["arn"]], (
        f"the filter must record the resolved destination ARN: {filters!r}"
    )

    stream = _xname(ctx, "stream")
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    marker = _xname(ctx, "logmsg")
    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": marker}],
    )

    item = _poll_until(
        lambda: _get_item(ctx, table["name"], marker),
        lambda i: i is not None,
        timeout_s=300.0,
        interval_s=5.0,
        description="the subscription filter delivers the log event to the Lambda destination",
    )
    assert item["log_group"]["S"] == group, (
        f"the awslogs envelope must name the source log group: {item!r}"
    )
    assert item["log_stream"]["S"] == stream, (
        f"the awslogs envelope must name the source log stream: {item!r}"
    )
    assert item["message_type"]["S"] == "DATA_MESSAGE", (
        f"expected messageType DATA_MESSAGE in the awslogs envelope, got {item!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
