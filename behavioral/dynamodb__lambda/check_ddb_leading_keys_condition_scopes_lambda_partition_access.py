"""ddb-leading-keys-condition-scopes-lambda-partition-access."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "ddb-leading-keys-condition-scopes-lambda-partition-access"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "lambda"]


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


def _delete_log_group_if_present(ctx, name):
    """Delete the function's /aws/lambda/<name> log group; one never created is not an error."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


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
            ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, name))
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


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A dynamodb:LeadingKeys condition on a function's role allows GetItem and Query on the permitted partition
    key, while both are refused on another key with AccessDeniedException and the exact message and that
    partition's item still exists: the condition is DynamoDB's multi-tenant isolation.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, "tbl-tenants")
    ddb.put_item(
        TableName=table["name"],
        Item={"pk": {"S": "tenant-a"}, "payload": {"S": "sim2real-xsvc-tenant-a-value"}},
    )
    ddb.put_item(
        TableName=table["name"],
        Item={"pk": {"S": "tenant-b"}, "payload": {"S": "sim2real-xsvc-tenant-b-value"}},
    )

    code = """
        import os

        import boto3

        ddb = boto3.client("dynamodb")


        def handler(event, context):
            table = os.environ["TABLE"]
            out = {}
            for tenant in event["tenants"]:
                entry = {}
                try:
                    item = ddb.get_item(
                        TableName=table, Key={"pk": {"S": tenant}}, ConsistentRead=True
                    ).get("Item")
                    entry["get_payload"] = (item or {}).get("payload", {}).get("S")
                except Exception as exc:
                    err = getattr(exc, "response", None) or {}
                    entry["get_code"] = err.get("Error", {}).get(
                        "Code", type(exc).__name__
                    )
                    entry["get_message"] = err.get("Error", {}).get("Message")
                try:
                    resp = ddb.query(
                        TableName=table,
                        KeyConditionExpression="pk = :pk",
                        ExpressionAttributeValues={":pk": {"S": tenant}},
                    )
                    entry["query_count"] = resp["Count"]
                except Exception as exc:
                    err = getattr(exc, "response", None) or {}
                    entry["query_code"] = err.get("Error", {}).get(
                        "Code", type(exc).__name__
                    )
                    entry["query_message"] = err.get("Error", {}).get("Message")
                out[tenant] = entry
            return out
    """
    fn = _create_lambda(
        ctx,
        code,
        permissions=[
            {
                "Action": ["dynamodb:GetItem", "dynamodb:Query"],
                "Resource": table["arn"],
                "Condition": {
                    "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["tenant-a"]}
                },
            }
        ],
        env={"TABLE": table["name"]},
    )

    payload = _poll_until(
        lambda: _invoke_payload(ctx, fn["name"], {"tenants": ["tenant-a", "tenant-b"]}),
        lambda r: r.get("tenant-a", {}).get("get_payload") is not None,
        timeout_s=120.0,
        interval_s=5.0,
        description="the permitted partition is readable (IAM propagation)",
    )
    # Control: the permitted partition works for both access patterns.
    assert payload["tenant-a"]["get_payload"] == "sim2real-xsvc-tenant-a-value", payload
    assert payload["tenant-a"].get("query_count") == 1, (
        f"Query on the permitted leading key must return the single item: {payload['tenant-a']!r}"
    )
    # The rejection: same table, same actions, different leading key.
    assert payload["tenant-b"].get("get_code") == "AccessDeniedException", (
        f"GetItem outside the LeadingKeys condition must be denied, got {payload['tenant-b']!r} -- "
        "returning the item means the Condition block was ignored"
    )
    assert payload["tenant-b"].get("query_code") == "AccessDeniedException", (
        f"Query outside the LeadingKeys condition must be denied, got {payload['tenant-b']!r}"
    )
    _, partition, _, _, account, _ = table["arn"].split(":", 5)
    caller = f"arn:{partition}:sts::{account}:assumed-role/{fn['role_name']}/{fn['name']}"
    for op, action in (("get", "dynamodb:GetItem"), ("query", "dynamodb:Query")):
        expected = (
            f"User: {caller} is not authorized to perform: {action} on resource: {table['arn']} "
            f"because no identity-based policy allows the {action} action"
        )
        got = payload["tenant-b"].get(f"{op}_message")
        assert got == expected, f"{action} denial message: {got!r}, expected {expected!r}"
    # Effect absent, and provably not because the item is missing.
    assert "get_payload" not in payload["tenant-b"] or payload["tenant-b"]["get_payload"] is None, (
        f"no tenant-b payload may reach the caller: {payload['tenant-b']!r}"
    )
    admin_item = _get_item(ctx, table["name"], "tenant-b")
    assert admin_item and admin_item["payload"]["S"] == "sim2real-xsvc-tenant-b-value", (
        f"the denied partition's item must still exist: {admin_item!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
