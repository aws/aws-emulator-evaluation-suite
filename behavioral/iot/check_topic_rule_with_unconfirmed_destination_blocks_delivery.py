"""topic-rule-with-unconfirmed-destination-blocks-delivery."""
from __future__ import annotations

import io
import json
import re
import time
import urllib.error
import urllib.request
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-rule-with-unconfirmed-destination-blocks-delivery"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An enabled topic rule's HTTP action does not deliver while its destination is unconfirmed, and delivers
    the published marker once the destination is confirmed and enabled."""
    fn_name, fn_url = _create_confirming_endpoint(ctx)
    iot = ctx.client("iot")
    iot_data = ctx.client("iot-data")

    create_resp = iot.create_topic_rule_destination(
        destinationConfiguration={"httpUrlConfiguration": {"confirmationUrl": fn_url}}
    )
    dest_arn = create_resp["topicRuleDestination"]["arn"]
    ctx.on_cleanup(lambda: iot.delete_topic_rule_destination(arn=dest_arn))

    token = _poll_logs_for_token_with_resend(ctx, iot, dest_arn, fn_name, timeout_s=240.0)
    assert token, f"never observed a DestinationConfirmation token in {fn_name}'s logs for {dest_arn}"

    topic = f"sim2real/iot/ruledest/{ctx.unique_name('t')}"
    rule_name = ctx.unique_name("s2ridblk").replace("-", "_")
    iot.create_topic_rule(
        ruleName=rule_name,
        topicRulePayload={
            "sql": f"SELECT * FROM '{topic}'",
            "actions": [{"http": {"url": fn_url}}],
            "ruleDisabled": False,
        },
    )
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_name))

    blocked_marker = f"blocked-{uuid.uuid4()}"
    iot_data.publish(topic=topic, payload=json.dumps({"marker": blocked_marker}).encode())
    _assert_marker_absent(ctx, fn_name, blocked_marker, window_s=45.0)

    iot.confirm_topic_rule_destination(confirmationToken=token)
    # Confirmation leaves IN_PROGRESS asynchronously and rests at DISABLED until enabled.
    _poll_dest_status(iot, dest_arn, "DISABLED", timeout_s=60.0)
    iot.update_topic_rule_destination(arn=dest_arn, status="ENABLED")
    _poll_dest_status(iot, dest_arn, "ENABLED", timeout_s=60.0)

    delivered_marker = f"delivered-{uuid.uuid4()}"
    iot_data.publish(topic=topic, payload=json.dumps({"marker": delivered_marker}).encode())
    found = _poll_logs_for(
        ctx,
        fn_name,
        lambda msg: delivered_marker if delivered_marker in msg else None,
        timeout_s=180.0,
    )
    assert found == delivered_marker, (
        f"expected marker {delivered_marker!r} to appear in {fn_name}'s logs after confirm+enable, got {found!r}"
    )


_LAMBDA_SRC = """
import json


def handler(event, context):
    qsp = event.get("queryStringParameters") or {}
    token = qsp.get("confirmationToken")
    marker = None
    body_raw = event.get("body") or ""
    try:
        parsed = json.loads(body_raw) if body_raw else {}
    except Exception:
        parsed = {}
    if isinstance(parsed, dict):
        token = token or parsed.get("confirmationToken")
        marker = parsed.get("marker")
    print("SIM2REAL_HIT token=%s marker=%s" % (token, marker))
    return {"statusCode": 200, "body": "ok"}
"""


def _lambda_zip(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _create_confirming_endpoint(ctx):
    # IoT HTTP topic rule destinations call a public HTTPS endpoint: an API Gateway HTTP API fronts the
    # Lambda that logs the confirmation token and the delivered messages.
    lambda_client = ctx.client("lambda")
    iam = ctx.client("iam")
    apigw = ctx.client("apigatewayv2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fn_name = ctx.unique_name("sim2real-iot-ruledest2-")
    role_name = ctx.unique_name("sim2real-iot-ruledest2-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    zip_bytes = _lambda_zip(_LAMBDA_SRC)

    def _create():
        return lambda_client.create_function(
            FunctionName=fn_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=10,
            Publish=True,
        )

    fn_arn = _retry_on_codes(_create, codes=("InvalidParameterValueException",), timeout_s=60)["FunctionArn"]
    ctx.on_cleanup(lambda: lambda_client.delete_function(FunctionName=fn_name))
    lambda_client.get_waiter("function_active").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    api = apigw.create_api(Name=ctx.unique_name("sim2real-iot-ruledest2-api-"), ProtocolType="HTTP")
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))
    integration = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn_arn,
        PayloadFormatVersion="2.0",
    )
    apigw.create_route(ApiId=api_id, RouteKey="$default", Target=f"integrations/{integration['IntegrationId']}")
    apigw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    lambda_client.add_permission(
        FunctionName=fn_name,
        StatementId="AllowApiGatewayInvoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*",
    )
    endpoint_url = api["ApiEndpoint"] + "/"
    _self_test_endpoint_with_retry(ctx, fn_name, endpoint_url, timeout_s=60.0)
    return fn_name, endpoint_url


def _self_test_endpoint_with_retry(ctx, fn_name, url, timeout_s=60.0, interval_s=3.0):
    """POST a synthetic probe straight to the API Gateway endpoint and confirm it lands in
    the Lambda's own CloudWatch Logs -- proves the endpoint is warm and its invoke
    permission has propagated before IoT gets to make its own (limited-attempt)
    confirmation POST."""
    marker = f"selftest-{uuid.uuid4()}"
    payload = json.dumps({"marker": marker}).encode()
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            _url, _route = ctx.endpoint_route(url)
            req = urllib.request.Request(
                _url, data=payload, headers={"Content-Type": "application/json", **_route}, method="POST"
            )
            with urllib.request.urlopen(req, timeout=10, context=_ssl_context(ctx.http_verify)) as resp:
                resp.read()
        except urllib.error.HTTPError as exc:
            body = exc.read()
            last_err = AssertionError(f"HTTP {exc.code}: {body!r}")
            time.sleep(interval_s)
            continue
        except (urllib.error.URLError, TimeoutError) as exc:
            last_err = exc
            time.sleep(interval_s)
            continue
        seen = _scan_logs_for(ctx, fn_name, lambda msg, m=marker: m if m in msg else None, timeout_s=10.0, interval_s=2.0)
        if seen is not None:
            return
        last_err = RuntimeError(f"self-test marker {marker} not yet in the function's logs")
        time.sleep(interval_s)
    lam = ctx.client("lambda")
    diag = lam.invoke(
        FunctionName=fn_name, Payload=json.dumps({"body": json.dumps({"marker": "diag"})}).encode()
    )
    diag_payload = diag["Payload"].read()
    try:
        policy = lam.get_policy(FunctionName=fn_name)["Policy"]
    except ClientError as exc:
        policy = f"<get_policy failed: {exc}>"
    raise AssertionError(
        f"confirming endpoint {url} never became reachable/functional: {last_err}; "
        f"direct invoke FunctionError={diag.get('FunctionError')} payload={diag_payload!r}; "
        f"resource policy={policy}"
    )


def _poll_logs_for_token_with_resend(ctx, iot, dest_arn, fn_name, *, timeout_s=240.0, window_s=60.0):
    """IoT sends the DestinationConfirmation POST once, immediately on create. If that single
    attempt races endpoint warm-up, ask IoT to resend it (UpdateTopicRuleDestination ->
    IN_PROGRESS, exactly as the docs describe for reactivating a stalled confirmation) rather
    than waiting out one long window that a correct-but-slow endpoint could still miss."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        window = min(window_s, deadline - time.monotonic())
        token = _scan_logs_for(ctx, fn_name, _extract_token, timeout_s=window, interval_s=5.0)
        if token is not None:
            return token
        if time.monotonic() >= deadline:
            break
        iot.update_topic_rule_destination(arn=dest_arn, status="IN_PROGRESS")
    raise AssertionError(f"expected confirmation token never observed for {dest_arn} within {timeout_s}s")


def _retry_on_codes(fn, codes, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in codes:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _extract_token(message: str):
    match = re.search(r"SIM2REAL_HIT token=(\S+) marker=", message)
    if match and match.group(1) != "None":
        return match.group(1)
    return None


def _poll_logs_for(ctx, function_name, extractor, timeout_s=150.0, interval_s=5.0):
    value = _scan_logs_for(ctx, function_name, extractor, timeout_s=timeout_s, interval_s=interval_s)
    if value is None:
        raise AssertionError(
            f"expected log line not observed in /aws/lambda/{function_name} within {timeout_s}s"
        )
    return value


def _scan_logs_for(ctx, function_name, extractor, timeout_s=150.0, interval_s=5.0):
    """Return the first extracted value from the function's logs, or None if the window elapses."""
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{function_name}"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            resp = {"events": []}
        for event in resp.get("events", []):
            value = extractor(event["message"])
            if value:
                return value
        time.sleep(interval_s)
    return None


def _poll_dest_status(iot, arn, expected, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = iot.get_topic_rule_destination(arn=arn)["topicRuleDestination"]
        if last["status"] == expected:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"destination never reached {expected}, last={last}")


def _assert_marker_absent(ctx, function_name, marker, window_s=45.0, interval_s=5.0):
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{function_name}"
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{marker}"')
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            resp = {"events": []}
        if resp.get("events"):
            raise AssertionError(
                f"marker {marker} was unexpectedly delivered to an unconfirmed destination"
            )
        time.sleep(interval_s)


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
