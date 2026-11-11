"""apigw-http-api-lambda-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigw-http-api-lambda-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_LAMBDA_CODE = """
import json

def handler(event, context):
    print("HANDLED_REQUEST")
    return {"statusCode": 200, "body": json.dumps({"ok": True})}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An HTTP API integration lacking the lambda:InvokeFunction resource-policy statement fails to
    invoke the Lambda backend (500, Lambda never runs); granting the statement fixes it."""
    role_arn = _create_lambda_role(ctx)
    fn = _create_lambda_function(ctx, role_arn, _LAMBDA_CODE)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{fn['name']}"
    try:
        logs.create_log_group(logGroupName=log_group, tags={"sim2real:managed": "true"})
        ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    except logs.exceptions.ResourceAlreadyExistsException:
        pass

    apigw = ctx.client("apigatewayv2")
    name = ctx.unique_name("sim2real-httpapi-")
    api = apigw.create_api(Name=name, ProtocolType="HTTP", Tags={"sim2real:managed": "true"})
    api_id = api["ApiId"]
    endpoint = api["ApiEndpoint"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    integration = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        PayloadFormatVersion="2.0",
        IntegrationMethod="POST",
    )
    apigw.create_route(
        ApiId=api_id, RouteKey="GET /hit", Target=f"integrations/{integration['IntegrationId']}"
    )
    apigw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)

    url = f"{endpoint}/hit"
    lam = ctx.client("lambda")

    # --- calibration barrier: measure how long THIS account currently takes to surface an
    # invocation's log line, via a DIRECT invoke that bypasses the resource policy entirely
    # (the check's own IAM identity, never the missing apigateway-service-principal grant).
    # The absence window below is sized off this measured latency, never a guessed sleep.
    t_calib_ms = _now_ms()
    calib_resp = lam.invoke(FunctionName=fn["name"], InvocationType="RequestResponse", Payload=b"{}")
    assert not calib_resp.get("FunctionError"), (
        f"calibration invoke raised, so a latency measured from it would be meaningless: "
        f"{calib_resp.get('FunctionError')}"
    )
    calib_latency_s = _poll_for_log_latency(ctx, log_group, "HANDLED_REQUEST", t_calib_ms, timeout_s=90.0)
    assert calib_latency_s is not None, (
        "calibration barrier failed: a direct invoke produced no matching log line, so an "
        "absence measured later against this log group would prove nothing"
    )

    # No lambda:InvokeFunction resource-policy statement has been granted yet. Poll past
    # the initial deploy-propagation window (transient 404s) until we get a definitive,
    # non-propagation response.
    t_negative_start_ms = _now_ms()
    status, body = _poll_http_get_any_terminal(ctx, url, timeout_s=90)
    assert status == 500, f"expected 500 without invoke permission, got {status}: {body}"
    payload = json.loads(body)
    assert payload["message"] == "Internal Server Error", (
        f"expected body.message == 'Internal Server Error', got: {payload}"
    )

    # Effect absent: Lambda was never actually invoked. Hold for >= 3x the just-measured
    # calibration latency (never a bare sleep) so a target that is merely slow to deliver
    # logs cannot be mistaken for one that correctly withheld the invocation, and bail out
    # immediately if the marker shows up (a real defect, not something worth waiting out).
    absence_window_s = max(3.0 * calib_latency_s, 15.0)
    handled = _await_log_marker_or_absence(ctx, log_group, "HANDLED_REQUEST", t_negative_start_ms, absence_window_s)
    assert not handled, (
        f"Lambda was invoked (log marker observed) despite no invoke permission being granted, "
        f"within a window of {absence_window_s:.0f}s (>= 3x the {calib_latency_s:.1f}s calibration latency)"
    )

    # Positive control: granting exactly the missing permission makes the identical
    # call succeed and the function actually run.
    t_positive_start_ms = _now_ms()
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*",
    )
    ok_status, ok_body = _poll_http_get_any_terminal(ctx, url, timeout_s=90, want_status=200)
    assert ok_status == 200, f"expected 200 after granting permission, got {ok_status}: {ok_body}"
    ok_payload = json.loads(ok_body)
    assert ok_payload["ok"] is True, f"expected body.ok == True after granting permission, got: {ok_payload}"
    assert _poll_log_contains_since(ctx, log_group, "HANDLED_REQUEST", t_positive_start_ms, timeout_s=60.0), (
        "granting the permission did not result in the function actually running "
        "(no matching log line within 60s of the grant)"
    )


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lamrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_lambda_function(ctx, role_arn, code, handler="index.handler", timeout=10) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    zip_bytes = buf.getvalue()

    last_err = None
    resp = None
    for _ in range(15):
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Publish=True,
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded (role propagation?): {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))

    deadline = time.monotonic() + 60
    state = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg.get("State")
        if state == "Active":
            break
        time.sleep(2)
    if state != "Active":
        raise AssertionError(f"lambda function {name} never became Active (last state={state})")

    return {"name": name, "arn": resp["FunctionArn"]}


def _poll_http_get_any_terminal(ctx, url, timeout_s=90.0, interval_s=3.0, want_status=None):
    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        try:
            _url, _route = ctx.endpoint_route(url)
            with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=10) as resp:
                status = resp.status
                body = resp.read().decode()
        except urllib.error.HTTPError as e:
            status = e.code
            body = e.read().decode() if e.fp is not None else ""
        except urllib.error.URLError:
            time.sleep(interval_s)
            continue
        last = (status, body)
        if want_status is not None:
            if status == want_status:
                return status, body
        elif status != 404:
            return status, body
        time.sleep(interval_s)
    return last


def _now_ms() -> int:
    return int(time.time() * 1000)


def _log_contains_since(ctx, log_group, substring, start_time_ms):
    logs = ctx.client("logs")
    try:
        resp = logs.filter_log_events(logGroupName=log_group, startTime=start_time_ms)
    except logs.exceptions.ResourceNotFoundException:
        return False
    return any(substring in e.get("message", "") for e in resp.get("events", []))


def _poll_log_contains_since(ctx, log_group, substring, start_time_ms, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _log_contains_since(ctx, log_group, substring, start_time_ms):
            return True
        time.sleep(interval_s)
    return _log_contains_since(ctx, log_group, substring, start_time_ms)


def _poll_for_log_latency(ctx, log_group, substring, start_time_ms, timeout_s=90.0, interval_s=3.0):
    """Return elapsed wall-clock seconds until `substring` appears since start_time_ms, or
    None on timeout. Used to measure a real latency to calibrate an absence window against,
    instead of guessing one."""
    t0 = time.monotonic()
    deadline = t0 + timeout_s
    while time.monotonic() < deadline:
        if _log_contains_since(ctx, log_group, substring, start_time_ms):
            return time.monotonic() - t0
        time.sleep(interval_s)
    return None


def _await_log_marker_or_absence(ctx, log_group, substring, start_time_ms, window_s, interval_s=3.0):
    """Bounded retry that holds absence for `window_s`, returning True (and exiting
    immediately) the moment `substring` shows up, or False once the window elapses with
    nothing found. Never an unconditional sleep: every wait here has a deadline and can end
    early on the thing it is watching for."""
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        if _log_contains_since(ctx, log_group, substring, start_time_ms):
            return True
        time.sleep(min(interval_s, max(0.0, deadline - time.monotonic())))
    return _log_contains_since(ctx, log_group, substring, start_time_ms)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
