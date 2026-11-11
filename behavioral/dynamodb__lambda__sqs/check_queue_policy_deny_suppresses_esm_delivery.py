"""queue-policy-deny-suppresses-esm-delivery."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "queue-policy-deny-suppresses-esm-delivery"
GROUP = "data-delivery"
SERVICES = ["dynamodb", "lambda", "sqs"]


# ===== helpers =====

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


_SUCCEEDED = "<the call succeeded>"


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message, HTTP status) of the ClientError it raises.

    A call that succeeds returns _SUCCEEDED in every slot, a value no error code, message or
    status can equal, so a success can never read as a refusal.
    """
    try:
        fn()
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("Error", {}).get("Message"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
        )
    return (_SUCCEEDED, _SUCCEEDED, _SUCCEEDED)


def _retry_client_error(fn, *, codes, timeout_s=120.0, interval_s=3.0, description="call"):
    """Call fn() until it stops raising one of `codes`, with a bounded deadline.

    IAM propagation is real and slow: a resource policy naming a just-created role is rejected
    ("invalid principal") until IAM converges, and a service that must assume a brand-new role
    reports it cannot. This retries that window instead of sleeping blind — the deadline is the
    assertion, never a bare time.sleep.
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


def _assert_absent_for(probe, *, timeout_s, interval_s=5.0, description="effect"):
    """Poll probe() for a whole bounded window and fail if it EVER becomes truthy.

    The negative-delivery assertion: proving something does NOT arrive needs a watched window,
    not a single look and not a bare sleep.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        seen = probe()
        assert not seen, f"{description} must NOT have happened, but observed: {seen!r}"
        time.sleep(interval_s)


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_role(ctx, trust, inline_policy=None, kind=None):
    """Create an IAM role and register its (policies-then-role) teardown. Returns {name, arn}.

    `trust` is either a service principal string ("lambda.amazonaws.com") or a full trust-policy
    document, which is what the role-to-role AssumeRole checks need.
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


def _drop_log_group(ctx, fn_name):
    """Delete a Lambda's auto-created log group, tolerating its never having been created.

    A function that is never invoked has no /aws/lambda/<name>, and ResourceNotFoundException there
    is success, not a teardown failure.
    """
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
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
            # Registered BEFORE delete_function so LIFO teardown runs it AFTER the function is
            # gone; deleting /aws/lambda/<name> first would let the still-live function recreate
            # it. Note this narrows the race but does not close it: Lambda's log delivery creates
            # the group ASYNCHRONOUSLY, and it was measured reappearing ~3s after the whole run
            # (teardown included) had exited. An empty log group has no storage cost, so the
            # residue is free; closing it would need an unbounded post-teardown poll.
            ctx.on_cleanup(lambda: _drop_log_group(ctx, name))
            ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
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


def _create_queue(ctx, kind="q"):
    """Create a queue; register teardown. Returns {name, url, arn}."""
    sqs = ctx.client("sqs")
    name = _xname(ctx, kind)
    url = sqs.create_queue(QueueName=name, tags=dict(_xsvc_resource_tags()))["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"name": name, "url": url, "arn": arn}


def _queue_depth(ctx, url):
    """Visible + in-flight message count — the observable for 'nothing consumed it'."""
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return int(attrs["ApproximateNumberOfMessages"]) + int(
        attrs["ApproximateNumberOfMessagesNotVisible"]
    )


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An explicit Deny of sqs:ReceiveMessage with Principal "*" in the queue policy silently stops
    a working event source mapping (message stays queued, mapping still Enabled), a Deny aimed at the
    execution role does not, and removing the policy delivers that same message."""
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    table = _create_table(ctx, "tbl-esm")
    queue = _create_queue(ctx, "q-esm")

    code = """
        import os

        import boto3

        ddb = boto3.client("dynamodb")


        def handler(event, context):
            for record in event["Records"]:
                ddb.put_item(
                    TableName=os.environ["TABLE"],
                    Item={
                        "pk": {"S": record["body"]},
                        "source": {"S": record["eventSourceARN"]},
                    },
                )
            return {"count": len(event["Records"])}
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
                "Resource": queue["arn"],
            },
            {"Action": ["dynamodb:PutItem"], "Resource": table["arn"]},
        ],
        env={"TABLE": table["name"]},
    )

    esm = _retry_client_error(
        lambda: lam.create_event_source_mapping(
            EventSourceArn=queue["arn"], FunctionName=fn["name"], BatchSize=1, Enabled=True
        ),
        codes=("InvalidParameterValueException",),
        description="CreateEventSourceMapping while the execution role's SQS grant propagates",
    )
    ctx.on_cleanup(
        lambda: ctx.client("lambda").delete_event_source_mapping(UUID=esm["UUID"])
    )
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm["UUID"]),
        lambda r: r.get("State") == "Enabled",
        timeout_s=180.0,
        interval_s=5.0,
        description="the event source mapping reaches Enabled",
    )

    # Prove the pipe works before breaking anything.
    delivered_body = _xname(ctx, "msg-delivered")
    sqs.send_message(QueueUrl=queue["url"], MessageBody=delivered_body)
    item = _poll_until(
        lambda: _get_item(ctx, table["name"], delivered_body),
        lambda i: i is not None,
        timeout_s=180.0,
        interval_s=5.0,
        description="the ESM delivers the first message to the Lambda",
    )
    assert item["source"]["S"] == queue["arn"], (
        f"the record must carry the resolved event source ARN: {item!r}"
    )

    # CONTRAST leg: a Deny aimed at the execution role ARN does NOT suppress the poller's receive
    # (see the docstring). This is asserted, not assumed, because it is the half an emulator is
    # most likely to invert.
    role_deny = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyEsmRoleReceive",
                    "Effect": "Deny",
                    "Principal": {"AWS": fn["role_arn"]},
                    "Action": "sqs:ReceiveMessage",
                    "Resource": queue["arn"],
                }
            ],
        }
    )
    _retry_client_error(
        lambda: sqs.set_queue_attributes(
            QueueUrl=queue["url"], Attributes={"Policy": role_deny}
        ),
        codes=("InvalidAttributeValue", "InvalidParameterValue"),
        description="SetQueueAttributes naming the Lambda execution role (IAM propagation)",
    )
    _poll_until(
        lambda: sqs.get_queue_attributes(QueueUrl=queue["url"], AttributeNames=["Policy"]),
        lambda r: "DenyEsmRoleReceive" in r.get("Attributes", {}).get("Policy", ""),
        timeout_s=60.0,
        interval_s=2.0,
        description="the role-scoped deny policy is readable on the queue",
    )
    role_deny_body = _xname(ctx, "msg-role-deny")
    sqs.send_message(QueueUrl=queue["url"], MessageBody=role_deny_body)
    _poll_until(
        lambda: _get_item(ctx, table["name"], role_deny_body),
        lambda i: i is not None,
        timeout_s=180.0,
        interval_s=5.0,
        description=(
            "a queue-policy Deny naming the execution role does NOT stop ESM delivery -- the "
            "poller's receive is not authorized as that role"
        ),
    )

    # Break EXACTLY one thing: the same Deny of the same action, now not scoped to a principal.
    deny_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyAllReceive",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "sqs:ReceiveMessage",
                    "Resource": queue["arn"],
                }
            ],
        }
    )
    # The deny is in force, proven WITHOUT reference to the ESM: this caller can no longer
    # receive from its own queue. This is what makes the non-delivery below non-vacuous.
    #
    # SetQueueAttributes is RE-ISSUED on every poll rather than sent once. Measured: a policy
    # change made within ~60s of the previous one on the same queue can be dropped outright --
    # the role-scoped policy above stayed in force for a full 120s window when this was a single
    # call, while the same change applied to a policy that had been settled for minutes took
    # effect in under 30s. Re-issuing makes the bounded deadline the assertion either way, and an
    # identical SetQueueAttributes is idempotent.
    denial = _poll_until(
        lambda: _err(
            lambda: (
                sqs.set_queue_attributes(
                    QueueUrl=queue["url"], Attributes={"Policy": deny_policy}
                ),
                sqs.receive_message(
                    QueueUrl=queue["url"], MaxNumberOfMessages=1, WaitTimeSeconds=1
                ),
            )
        ),
        lambda r: r[0] != _SUCCEEDED,
        timeout_s=300.0,
        interval_s=10.0,
        description="the unscoped deny takes effect for this caller's own ReceiveMessage",
    )
    code, message, status = denial
    assert code == "AccessDenied", (
        f"an explicit resource-policy Deny must refuse ReceiveMessage with AccessDenied, got "
        f"{code}"
    )
    assert status == 403, f"the explicit Deny must answer HTTP 403, got {status}"
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected_message = (
        f"User: {caller_arn} is not authorized to perform: sqs:receivemessage on resource: "
        f"{queue['arn']} with an explicit deny in a resource-based policy"
    )
    assert message == expected_message, (
        f"the explicit Deny must name the caller, action and queue: expected "
        f"{expected_message!r}, got {message!r}"
    )

    suppressed_body = _xname(ctx, "msg-suppressed")
    sqs.send_message(QueueUrl=queue["url"], MessageBody=suppressed_body)
    # The negative: nothing may be delivered for a whole watched window.
    _assert_absent_for(
        lambda: _get_item(ctx, table["name"], suppressed_body),
        timeout_s=120.0,
        interval_s=5.0,
        description="delivery of the message while the queue policy denies ReceiveMessage",
    )
    # And the message is still sitting in the queue -- it was not consumed by anyone.
    depth = _queue_depth(ctx, queue["url"])
    assert depth >= 1, (
        f"the undelivered message must still be in the queue, depth={depth} -- if the queue is "
        "empty something consumed it despite the Deny"
    )
    # The suppression is SILENT: the mapping is still Enabled and reports no failure, so a caller
    # watching the ESM has no signal that its consumer has stopped.
    mapping = lam.get_event_source_mapping(UUID=esm["UUID"])
    assert mapping.get("State") == "Enabled", (
        f"the mapping must stay Enabled while the queue policy suppresses it, got "
        f"{mapping.get('State')}"
    )
    assert mapping.get("LastProcessingResult") in (None, ""), (
        f"the suppression must be silent -- the mapping reported "
        f"{mapping.get('LastProcessingResult')!r}"
    )

    # Control: remove ONLY the queue policy; the same message must then be delivered.
    # Re-issued per poll for the same reason as above. VisibilityTimeout=0 so this liveness probe
    # cannot hide the suppressed message from the poller it is about to be delivered to.
    _poll_until(
        lambda: _err(
            lambda: (
                sqs.set_queue_attributes(
                    QueueUrl=queue["url"], Attributes={"Policy": ""}
                ),
                sqs.receive_message(
                    QueueUrl=queue["url"],
                    MaxNumberOfMessages=1,
                    WaitTimeSeconds=1,
                    VisibilityTimeout=0,
                ),
            )
        ),
        lambda r: r[0] == _SUCCEEDED,
        timeout_s=300.0,
        interval_s=10.0,
        description="removing the policy restores this caller's own ReceiveMessage",
    )
    resumed = _poll_until(
        lambda: _get_item(ctx, table["name"], suppressed_body),
        lambda i: i is not None,
        timeout_s=300.0,
        interval_s=10.0,
        description="removing the queue policy resumes ESM delivery of the same message",
    )
    assert resumed["pk"]["S"] == suppressed_body, resumed


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
