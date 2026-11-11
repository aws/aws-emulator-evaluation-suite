"""ddb-resource-policy-alone-grants-lambda-role-get-item."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "ddb-resource-policy-alone-grants-lambda-role-get-item"
GROUP = "arn-resolution"
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


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of its refusal, raising if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal but the call succeeded: {result!r}")


def _retry_client_error(fn, *, codes, timeout_s=120.0, interval_s=3.0, description="call"):
    """Call fn() until it stops raising one of `codes`, failing after timeout_s.

    A resource policy naming a just-created role is rejected as an invalid principal until IAM
    converges.
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
    """Create an IAM role and register its teardown; return {name, arn}.

    `trust` is a service principal string or a full trust-policy document.
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
    """Create a Lambda, retrying through IAM role propagation, then wait until Active.

    Registers function and log group teardown; a `handler` def is aliased to `lambda_handler`.
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


def _create_lambda(ctx, handler_code, permissions=None, env=None, timeout=30, memory=128,
                   runtime="python3.12"):
    """Create a Lambda whose execution role allows only `permissions` (plus logs).

    Returns {name, arn, role_name, role_arn}; the role ARN is the resource-policy principal.
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
    """Invoke and return the parsed result payload, asserting the handler did not fault."""
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


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A table resource policy naming the Lambda execution role alone lets that role GetItem (the
    role has no dynamodb permission), while an identical table with no policy still denies it.
    """
    ddb = ctx.client("dynamodb")
    granted = _create_table(ctx, "tbl-granted")
    control = _create_table(ctx, "tbl-control")
    for table in (granted["name"], control["name"]):
        ddb.put_item(
            TableName=table,
            Item={
                "pk": {"S": "tenant-a"},
                "payload": {"S": "sim2real-xsvc-resource-policy-value"},
            },
        )

    code = """
        import boto3

        ddb = boto3.client("dynamodb")


        def handler(event, context):
            out = {}
            for label, table in event["tables"].items():
                try:
                    item = ddb.get_item(
                        TableName=table, Key={"pk": {"S": "tenant-a"}}, ConsistentRead=True
                    ).get("Item")
                    out[label] = {"payload": (item or {}).get("payload", {}).get("S")}
                except Exception as exc:
                    err = getattr(exc, "response", None) or {}
                    out[label] = {
                        "code": err.get("Error", {}).get("Code", type(exc).__name__)
                    }
            return out
    """
    # No dynamodb permission whatsoever on the execution role.
    fn = _create_lambda(ctx, code, permissions=[])
    event = {"tables": {"granted": granted["name"], "control": control["name"]}}

    before = _invoke_payload(ctx, fn["name"], event)
    assert before["granted"].get("code") == "AccessDeniedException", (
        f"a role with no dynamodb permission must be denied before the resource policy: {before!r}"
    )

    _retry_client_error(
        lambda: ddb.put_resource_policy(
            ResourceArn=granted["arn"],
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowLambdaRoleGetItem",
                            "Effect": "Allow",
                            "Principal": {"AWS": fn["role_arn"]},
                            "Action": "dynamodb:GetItem",
                            "Resource": granted["arn"],
                        }
                    ],
                }
            ),
        ),
        codes=("ValidationException", "MalformedPolicyDocumentException"),
        description="PutResourcePolicy naming the Lambda execution role (IAM propagation)",
    )

    after = _poll_until(
        lambda: _invoke_payload(ctx, fn["name"], event),
        lambda r: r.get("granted", {}).get("payload") is not None,
        timeout_s=120.0,
        interval_s=5.0,
        description="the table resource policy authorizes the Lambda role's GetItem",
    )
    assert after["granted"]["payload"] == "sim2real-xsvc-resource-policy-value", (
        f"the resource policy must yield the exact typed attribute value: {after!r}"
    )
    # Control: the table with no resource policy still denies the same role.
    assert after["control"].get("code") == "AccessDeniedException", (
        f"the control table has no resource policy and must stay denied: {after!r}"
    )
    stored = ddb.get_resource_policy(ResourceArn=granted["arn"])
    assert fn["role_arn"] in stored["Policy"], (
        f"GetResourcePolicy must round-trip the role ARN principal: {stored!r}"
    )
    code, message = _err(lambda: ddb.get_resource_policy(ResourceArn=control["arn"]))
    assert code == "PolicyNotFoundException", (
        f"the control table must genuinely have no resource policy: {code!r}: {message!r}"
    )
    assert message == (
        f"Resource-based policy not found for the provided ResourceArn: {control['arn']}"
    ), message


def _delete_log_group_if_present(ctx, log_group_name: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group_name)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
