"""eventbridge-target-missing-lambda-permission-not-invoked."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-target-missing-lambda-permission-not-invoked"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "s3"]


@tags("axis:negative-delivery", "cap:c3", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Without an AddPermission grant for events.amazonaws.com the target is never invoked, while
    a granted control rule published at the same time is; granting the permission on the subject
    rule then lets the same event through."""
    ddb = ctx.client("dynamodb")
    events = ctx.client("events")
    lam = ctx.client("lambda")

    code = textwrap.dedent(
        """
        import boto3, os
        ddb = boto3.client("dynamodb")
        TABLE = os.environ["TABLE"]

        def lambda_handler(event, context):
            ddb.put_item(TableName=TABLE, Item={"pk": {"S": event["id"]}})
            return {"ok": True}
        """
    )

    table_subject = _create_table(ctx)
    table_control = _create_table(ctx)

    fn_subject = _create_lambda(
        ctx,
        code,
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": table_subject["arn"]}],
        env={"TABLE": table_subject["name"]},
    )
    fn_control = _create_lambda(
        ctx,
        code,
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": table_control["arn"]}],
        env={"TABLE": table_control["name"]},
    )

    rule_subject_name = ctx.unique_name("rule-no-perm-")
    subject_rule = events.put_rule(
        Name=rule_subject_name,
        EventPattern=json.dumps(
            {"source": ["check.noperm.subject"], "detail-type": ["NoPermEvent"]}
        ),
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_subject_name))
    # Deliberately withhold lambda:AddPermission (no resource-based policy grant) -- this rule is
    # the subject under test.
    events.put_targets(Rule=rule_subject_name, Targets=[{"Id": "t", "Arn": fn_subject["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_subject_name, Ids=["t"]))

    rule_control_name = ctx.unique_name("rule-with-perm-")
    control_rule = events.put_rule(
        Name=rule_control_name,
        EventPattern=json.dumps(
            {"source": ["check.noperm.control"], "detail-type": ["NoPermEvent"]}
        ),
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_control_name))
    lam.add_permission(
        FunctionName=fn_control["name"],
        StatementId="AllowEventsInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=control_rule["RuleArn"],
    )
    events.put_targets(Rule=rule_control_name, Targets=[{"Id": "t", "Arn": fn_control["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_control_name, Ids=["t"]))

    def publish(source: str) -> None:
        events.put_events(Entries=[{"Source": source, "DetailType": "NoPermEvent", "Detail": "{}"}])

    def has_item(table_name: str) -> bool:
        return bool(ddb.scan(TableName=table_name, Limit=1).get("Items", []))

    # One fan-out, same instant, so no propagation delta exists between subject and control.
    # EventBridge permanently drops events sent before a rule/target is live, so republish both
    # on every poll until the control is proven reachable. Each writes to its OWN table, so
    # presence there is unambiguous -- no dependence on the delivered event's "id" matching the
    # PutEvents EventId, which is not a relation this run should assume.
    def probe_control() -> bool:
        publish("check.noperm.subject")
        publish("check.noperm.control")
        return has_item(table_control["name"])

    control_landed = _wait_for_effect(
        probe_control,
        lambda ok: ok,
        timeout_s=180,
        interval_s=5.0,
        description="control (permission granted) target invoked",
    )
    assert control_landed, (
        "control target (permission granted) was never invoked, so the subject's absence proves "
        "nothing about the missing-permission wiring"
    )

    # The barrier: the control has just been proven reachable on this exact wiring and instant, so
    # what matters here is confirmation, not duration. A freeze detector -- repeated independent
    # reads rather than one sleep-then-check -- turns the margin into N consecutive reads that all
    # confirm nothing landed.
    for _ in range(4):
        assert not has_item(table_subject["name"]), (
            "EventBridge invoked the subject Lambda despite missing resource-based invoke "
            "permission (an item landed in the subject table)"
        )
        time.sleep(5.0)

    # Close the loop: grant the withheld permission on the subject's own rule and prove the
    # identical wiring now delivers -- so the absence above was the permission, not a rule that was
    # never reachable at all.
    lam.add_permission(
        FunctionName=fn_subject["name"],
        StatementId="AllowEventsInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=subject_rule["RuleArn"],
    )

    def probe_subject_after_grant() -> bool:
        publish("check.noperm.subject")
        return has_item(table_subject["name"])

    repaired = _wait_for_effect(
        probe_subject_after_grant,
        lambda ok: ok,
        timeout_s=180,
        interval_s=5.0,
        description="subject target invoked after granting the withheld permission",
    )
    assert repaired, (
        "granting the withheld invoke permission did not restore delivery to the subject target"
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
    # IAM role trust/permission propagation is bounded downstream, in
    # _create_function_with_retry's retry-on-"cannot be assumed" loop, rather than by a blind
    # sleep here.
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


def _delete_log_group_if_present(ctx, log_group: str) -> None:
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
            # The function creates /aws/lambda/<name> on first invoke and the group outlives the
            # function, so delete it too; a function never invoked has no log group to delete.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
