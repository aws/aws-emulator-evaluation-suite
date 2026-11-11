"""e2e-topic-rule-destination-confirm-then-deliver."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-topic-rule-destination-confirm-then-deliver"
GROUP = "e2e"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An HTTP topic rule destination starts IN_PROGRESS, is confirmed with the token IoT
    posts to the confirmation URL, and only after that confirmation is a rule created and
    successfully republishes a real MQTT message to it."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    apigw = ctx.client("apigatewayv2")
    ddb = ctx.client("dynamodb")
    iot = ctx.client("iot")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    table_name = ctx.unique_name("sim2real-httpdest-tbl-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    role_name = ctx.unique_name("sim2real-httpdest-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_exec_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn))
    write_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "dynamodb:PutItem",
                "Resource": f"arn:aws:dynamodb:{ctx.region}:*:table/{table_name}",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="write-recorder", PolicyDocument=json.dumps(write_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="write-recorder"))

    function_name = ctx.unique_name("sim2real-httpdest-fn-")
    zip_bytes = _build_recorder_zip(table_name)
    ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
    function_arn = _create_function_with_retry(lam, function_name, role_arn, zip_bytes)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    # Diagnostic: invoke the recorder directly (bypassing API Gateway entirely) to prove the
    # Lambda code itself is sound -- isolates a Lambda-code bug from an API Gateway/permission
    # problem before we start debugging the public HTTP path.
    direct_probe_marker = ctx.unique_name("direct-invoke-")
    direct_resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps({"body": json.dumps({"probe": direct_probe_marker})}).encode(),
    )
    direct_payload = json.loads(direct_resp["Payload"].read())
    assert direct_resp.get("FunctionError") is None, f"recorder Lambda crashed on direct invoke: {direct_payload}"
    assert _find_record_with_marker(ddb, table_name, direct_probe_marker) is not None, (
        f"recorder Lambda ran but did not persist the direct-invoke probe: {direct_payload}"
    )

    # Front the recorder with an API Gateway HTTP API, a publicly reachable HTTPS endpoint
    # that IoT HTTP destinations can call.
    # Built explicitly (integration + "$default" route + auto-deployed "$default" stage) rather
    # than via "quick create", since quick create's generated route can fail to match a bare
    # root-path request.
    api = apigw.create_api(
        Name=ctx.unique_name("sim2real-httpdest-api-"),
        ProtocolType="HTTP",
        Tags={"sim2real:managed": "true"},
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))
    integration = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=function_arn,
        PayloadFormatVersion="2.0",
    )
    apigw.create_route(ApiId=api_id, RouteKey="$default", Target=f"integrations/{integration['IntegrationId']}")
    apigw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    lam.add_permission(
        FunctionName=function_name,
        StatementId="AllowApiGatewayInvoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*",
    )
    receiver_url = api["ApiEndpoint"] + "/"



    # Self-test the public API Gateway endpoint end-to-end (permission propagation + cold
    # start) BEFORE creating the IoT destination -- IoT only gets a single immediate
    # confirmation attempt (plus whatever we trigger via resend), so the endpoint must already
    # be verified reachable rather than discovered broken only after IoT's own attempt is spent.
    _self_test_endpoint_with_retry(ctx, ddb, table_name, receiver_url, timeout_s=_budget_s(ctx, 60.0))

    # Creating the destination makes IoT immediately POST a DestinationConfirmation message
    # (containing confirmationToken) to receiver_url -- the recorder Lambda persists it.
    destination = iot.create_topic_rule_destination(
        destinationConfiguration={"httpUrlConfiguration": {"confirmationUrl": receiver_url}}
    )["topicRuleDestination"]
    destination_arn = destination["arn"]
    ctx.on_cleanup(lambda: _delete_destination(iot, destination_arn))

    assert destination["status"] == "IN_PROGRESS", (
        f"expected a freshly created HTTP topic rule destination to start IN_PROGRESS, "
        f"got {destination['status']!r}"
    )

    confirmation_token = _poll_for_confirmation_token_with_resend(
        ctx, iot, ddb, table_name, destination_arn, timeout_s=45.0, resends=3
    )
    iot.confirm_topic_rule_destination(confirmationToken=confirmation_token)
    # Confirming only proves ownership of the endpoint: the destination leaves IN_PROGRESS
    # asynchronously and rests at DISABLED until it is explicitly moved to ENABLED.
    confirmed_status = _poll_until(
        lambda: iot.get_topic_rule_destination(arn=destination_arn)["topicRuleDestination"]["status"],
        lambda status: status != "IN_PROGRESS",
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=1,
        ctx=ctx,
    )
    assert confirmed_status == "DISABLED", (
        f"expected a confirmed destination to rest at DISABLED, got {confirmed_status!r}"
    )
    iot.update_topic_rule_destination(arn=destination_arn, status="ENABLED")
    _poll_until(
        lambda: iot.get_topic_rule_destination(arn=destination_arn)["topicRuleDestination"]["status"],
        lambda status: status == "ENABLED",
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=1,
        ctx=ctx,
    )

    # Only NOW -- after confirmation -- do we create a rule republishing to the destination.
    # This mirrors the real workflow: an HTTP action destination must be confirmed before a
    # rule can be built to depend on it for delivery.
    rule_name = ctx.unique_name("sim2real_httpdest_rule_")
    topic = f"sim2real/{rule_name}"
    iot.create_topic_rule(
        ruleName=rule_name,
        topicRulePayload={
            "sql": f"SELECT * FROM '{topic}'",
            "actions": [{"http": {"url": receiver_url}}],
            "ruleDisabled": False,
        },
        tags="sim2real:managed=true",
    )
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_name))

    iot_data = _iot_data_client(ctx)
    after_marker = ctx.unique_name("after-confirm-")
    iot_data.publish(topic=topic, qos=1, payload=json.dumps({"marker": after_marker}).encode())

    delivered = _poll_until(
        lambda: _find_record_with_marker(ddb, table_name, after_marker),
        lambda item: item is not None,
        timeout_s=_budget_s(ctx, 45.0),
        interval_s=1,
        ctx=ctx,
    )
    assert delivered is not None and after_marker in delivered["body"]["S"], (
        f"expected the republished MQTT message (marker {after_marker!r}) to be delivered to the "
        f"confirmed HTTP destination and recorded in DynamoDB, got {delivered!r}"
    )



def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _delete_destination(iot, arn: str) -> None:
    iot.delete_topic_rule_destination(arn=arn)


def _self_test_endpoint_with_retry(ctx, ddb, table_name: str, receiver_url: str, *, timeout_s: float) -> None:
    """POST a synthetic probe straight to the API Gateway endpoint and confirm it lands in
    DynamoDB -- proves the endpoint is truly warm and its permissions have propagated before
    IoT gets to make its own (limited-attempt) confirmation POST."""
    marker = f"selftest-{time.monotonic_ns()}"
    payload = json.dumps({"messageType": "SelfTestProbe", "confirmationToken": marker}).encode()
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            _url, _route = ctx.endpoint_route(receiver_url)
            req = urllib.request.Request(
                _url, data=payload, headers={**({"Content-Type": "application/json"}), **_route}, method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_err = exc
            time.sleep(1)
            continue
        if _find_record_with_marker(ddb, table_name, marker) is not None:
            return
        error_item = _find_error_record(ddb, table_name)
        last_err = AssertionError(
            f"probe POST returned but was never recorded in DynamoDB (recorder error: {error_item})"
        )
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError("the API Gateway endpoint recording a self-test probe: the run budget ended first; not graded")
    raise AssertionError(f"API Gateway endpoint never became reachable/functional: {last_err}")


def _find_error_record(ddb, table_name: str) -> str | None:
    resp = ddb.scan(TableName=table_name)
    for item in resp.get("Items", []):
        if item.get("id", {}).get("S", "").endswith("-error"):
            return item.get("body", {}).get("S", "")
    return None



def _create_function_with_retry(lam, function_name: str, role_arn: str, zip_bytes: bytes) -> str:
    """IAM role trust propagation can lag; retry CreateFunction on the well-known transient
    InvalidParameterValueException for a role botocore just created, bounded (not a fixed sleep
    disguised as the wait -- each attempt is a real probe of the actual condition)."""
    last_exc = None
    for _ in range(10):
        try:
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="recorder.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=15,
                MemorySize=128,
                Tags={"sim2real:managed": "true"},
            )
            return resp["FunctionArn"]
        except lam.exceptions.InvalidParameterValueException as exc:  # noqa: PERF203
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"CreateFunction never succeeded after IAM propagation retries: {last_exc}")


def _find_record_with_marker(ddb, table_name: str, marker: str) -> dict | None:
    resp = ddb.scan(TableName=table_name)
    for item in resp.get("Items", []):
        if marker in item.get("body", {}).get("S", ""):
            return item
    return None


def _poll_for_confirmation_token(ddb, table_name: str, destination_arn: str, *, timeout_s: float) -> str | None:
    """Return the confirmation token IoT posted for the destination, or None if none arrived in the window."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ddb.scan(TableName=table_name)
        for item in resp.get("Items", []):
            body_str = item.get("body", {}).get("S", "")
            if not body_str:
                continue
            try:
                body = json.loads(body_str)
            except (json.JSONDecodeError, ValueError):
                continue
            if body.get("messageType") == "DestinationConfirmation" and body.get("arn") == destination_arn:
                return body["confirmationToken"]
        time.sleep(1)
    return None


def _poll_for_confirmation_token_with_resend(
    ctx, iot, ddb, table_name: str, destination_arn: str, *, timeout_s: float, resends: int
) -> str:
    """The very first confirmation POST can race a still-propagating API Gateway/Lambda
    permission. Rather than one long wait, poll in short windows and, between windows, ask IoT
    to resend the confirmation request (UpdateTopicRuleDestination -> IN_PROGRESS) exactly as
    the docs describe for reactivating a stalled confirmation."""
    for attempt in range(resends + 1):
        token = _poll_for_confirmation_token(
            ddb, table_name, destination_arn, timeout_s=_budget_s(ctx, timeout_s)
        )
        if token is not None:
            return token
        if attempt < resends:
            iot.update_topic_rule_destination(arn=destination_arn, status="IN_PROGRESS")
    if _budget_spent(ctx):
        raise TimeoutError("a DestinationConfirmation message for our destination: the run budget ended first; not graded")
    raise AssertionError("never observed a DestinationConfirmation message for our destination")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, ctx=None):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("topic rule destination wait condition: the run budget ended first; not graded")
    raise AssertionError(f"condition never became true within {timeout_s}s (last value: {value!r})")


def _build_recorder_zip(table_name: str) -> bytes:
    code = f"""
import json
import time
import boto3

_table_name = {table_name!r}


def handler(event, context):
    try:
        body = event.get("body") or "{{}}"
        ddb = boto3.resource("dynamodb").Table(_table_name)
        ddb.put_item(
            Item={{
                "id": context.aws_request_id,
                "ts": int(time.time() * 1000),
                "body": body,
            }}
        )
        return {{"statusCode": 200, "body": "ok"}}
    except Exception as exc:  # noqa: BLE001 -- surface any failure as a 200 so we can see it
        try:
            boto3.resource("dynamodb").Table(_table_name).put_item(
                Item={{
                    "id": context.aws_request_id + "-error",
                    "ts": int(time.time() * 1000),
                    "body": json.dumps({{"error": str(exc)}}),
                }}
            )
        except Exception:
            pass
        return {{"statusCode": 200, "body": "error-recorded"}}
"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("recorder.py", code)
    return buf.getvalue()


def _iot_data_client(ctx):
    iot = ctx.client("iot")
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return ctx.client("iot-data", endpoint_url=ctx.endpoint_url(endpoint))


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
