"""apigw-integration-timeout-maps-to-504-and-does-not-cancel-the-lambda."""
from __future__ import annotations

import io
import json
import random
import string
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags

CHECK = "apigw-integration-timeout-maps-to-504-and-does-not-cancel-the-lambda"
GROUP = "methods-integrations"
SERVICES = ["apigateway", "lambda"]

_SLEEP_S = 12                    # how long the backend takes to answer
_SLOW_TIMEOUT_MS = 3000          # integration timeout for the /slow resource
_FAST_TIMEOUT_MS = 29000         # documented maximum, used for the control and the restore
_LAMBDA_TIMEOUT_S = 30
_PROPAGATION_S = 240.0
_SIDE_CHANNEL_S = 90.0


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff."""
    from botocore.exceptions import ClientError
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


def _ignore_not_found(fn):
    """Teardown helper: a resource already gone is not a cleanup failure. Any other error
    still raises, so a leak is never hidden."""
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException",
                                                 "NoSuchEntity", "AWS.SimpleQueueService."
                                                 "NonExistentQueue"):
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry; RAISES on the deadline rather than returning its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s, last={last!r}")


def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise AssertionError(f"root ('/') resource not found on restApiId={api_id!r}")


def _http(method, url, headers=None, timeout=60.0):
    """HTTP request; returns (status, lowercased headers, body text, elapsed seconds)."""
    req = urllib.request.Request(url, method=method, headers=headers or {})
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode(errors="replace"), time.monotonic() - started)
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode(errors="replace"), time.monotonic() - started)


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _drain(sqs, queue_url):
    """Receive-and-delete everything currently visible; returns the parsed bodies."""
    out = []
    for _ in range(6):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=1)
        messages = resp.get("Messages", [])
        if not messages:
            break
        for msg in messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            out.append(json.loads(msg["Body"]))
    return out


def _backend_zip(queue_url, sleep_s, marker):
    """A Lambda proxy handler that takes `sleep_s` to answer and reports its COMPLETION on an
    SQS queue — the side channel that shows whether API Gateway's timeout cancelled it."""
    code = f"""
import json
import time

import boto3

_QUEUE_URL = {queue_url!r}
_SLEEP_S = {sleep_s!r}
_MARKER = {marker!r}


def handler(event, context):
    leg = (event.get("queryStringParameters") or {{}}).get("leg", "unknown")
    time.sleep(_SLEEP_S)
    boto3.client("sqs").send_message(
        QueueUrl=_QUEUE_URL,
        MessageBody=json.dumps({{
            "leg": leg,
            "marker": _MARKER,
            "requestId": context.aws_request_id,
        }}),
    )
    return {{
        "statusCode": 200,
        "headers": {{"Content-Type": "application/json"}},
        "body": json.dumps({{"marker": _MARKER, "leg": leg}}),
    }}
"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


# timing:real-time — lease: 3 s https://docs.aws.amazon.com/apigateway/latest/developerguide/limits.html
@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Lambda proxy backend outliving `timeoutInMillis` gets a 504 INTEGRATION_TIMEOUT at the
    configured 3 s deadline, not the 29 s default, yet the Lambda is not cancelled: its SQS write
    lands after the client has the 504, and restoring 29000 ms makes the same request return 200.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/supported-gateway-response-types.html"""
    ag = ctx.client("apigateway")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    marker = f"sim2real-{_unique_token()}"
    # Distinct from `marker`: the customised INTEGRATION_TIMEOUT template below embeds
    # "timeout-<gw_marker>", which would otherwise contain `marker` as a substring and make
    # the effect-absent check unsatisfiable on ANY target, correct or not.
    gw_marker = f"sim2real-gw-{_unique_token()}"

    # ---- side channel ------------------------------------------------------------------
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-apigwto-"),
        tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sqs.delete_queue(QueueUrl=queue_url)))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    # ---- execution role ----------------------------------------------------------------
    role_name = ctx.unique_name("sim2real-behav-apigwto-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=role_name)))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sqs-send",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage",
                           "Resource": queue_arn}],
        }))
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sqs-send")))
    basic = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic)
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic)))

    # ---- the slow backend --------------------------------------------------------------
    function_name = ctx.unique_name("sim2real-behav-apigwto-fn-")

    def _try_create():
        from botocore.exceptions import ClientError
        try:
            return lam.create_function(
                FunctionName=function_name, Runtime="python3.12", Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _backend_zip(queue_url, _SLEEP_S, marker)},
                Timeout=_LAMBDA_TIMEOUT_S, Tags={"sim2real": CHECK})
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                return None      # the role is not assumable by Lambda yet; retry
            raise

    function_arn = _poll_until(
        _try_create, lambda result: result is not None, timeout_s=90.0, interval_s=3.0,
        description="the new IAM role becoming assumable so CreateFunction succeeds",
    )["FunctionArn"]
    # The function's log group appears on its first invocation; registered first so it runs
    # after the function is deleted.
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")))
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: lam.delete_function(FunctionName=function_name)))

    # ---- the API: two resources, one Lambda, differing ONLY in timeoutInMillis ----------
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"), description=f"sim2real {CHECK}",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK}))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    lam.add_permission(
        FunctionName=function_name, StatementId="apigw-invoke",
        Action="lambda:InvokeFunction", Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*/*")

    integration_uri = (f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
                       f"{function_arn}/invocations")
    resources = {}
    for path_part, timeout_ms in (("fast", _FAST_TIMEOUT_MS), ("slow", _SLOW_TIMEOUT_MS)):
        resource_id = _retry_throttled(lambda pp=path_part: ag.create_resource(
            restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=pp))["id"]
        resources[path_part] = resource_id
        ctx.on_cleanup(lambda rid=resource_id: _retry_throttled(
            lambda: ag.delete_resource(restApiId=api_id, resourceId=rid)))
        _retry_throttled(lambda rid=resource_id: ag.put_method(
            restApiId=api_id, resourceId=rid, httpMethod="GET", authorizationType="NONE"))
        _retry_throttled(lambda rid=resource_id, tm=timeout_ms: ag.put_integration(
            restApiId=api_id, resourceId=rid, httpMethod="GET", type="AWS_PROXY",
            integrationHttpMethod="POST", uri=integration_uri, timeoutInMillis=tm))

    _retry_throttled(lambda: ag.put_gateway_response(
        restApiId=api_id, responseType="INTEGRATION_TIMEOUT",
        responseTemplates={"application/json":
                           '{"gw":"timeout-%s","type":"$context.error.responseType"}'
                           % gw_marker}))

    stage = f"s{_unique_token()}"
    deployment = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment,
        tags={"sim2real": CHECK}))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage)))

    fast_url = _apigw_url(ctx, api_id, stage, "/fast") + "?leg=fast"
    slow_url = _apigw_url(ctx, api_id, stage, "/slow") + "?leg=slow"

    # ---- beat 1: positive control on the 29000ms twin -----------------------------------
    # Lambda permission and stage propagation can lag, so the FIRST touch polls; every later
    # observation is a single unretried request.
    def _probe_fast():
        status, _h, text, elapsed = _http("GET", fast_url, timeout=60.0)
        return status, text, elapsed

    fast_status, fast_text, fast_elapsed = _poll_until(
        _probe_fast, lambda r: r[0] == 200, timeout_s=_PROPAGATION_S, interval_s=8.0,
        description=(
            f"GET {fast_url} (timeoutInMillis={_FAST_TIMEOUT_MS}) returning 200 through the "
            f"Lambda proxy integration"
        ),
    )
    assert marker in fast_text, (
        f"positive control: the {_FAST_TIMEOUT_MS}ms twin must return the backend's own "
        f"marker {marker!r}, got {fast_text[:200]!r}"
    )
    # time semantic: the backend sleeps _SLEEP_S before it answers, so the proxied 200
    # cannot arrive sooner.
    assert fast_elapsed >= float(_SLEEP_S), (
        f"positive control: the backend sleeps {_SLEEP_S}s, so the 200 must take at least "
        f"that long — got {fast_elapsed:.2f}s, which means the backend did not really run and "
        f"the timeout comparison below would be meaningless"
    )
    fast_messages = _poll_until(
        lambda: [m for m in _drain(sqs, queue_url) if m.get("leg") == "fast"],
        lambda found: len(found) >= 1, timeout_s=_SIDE_CHANNEL_S, interval_s=3.0,
        description="the control invocation's completion message on the SQS side channel",
    )
    assert fast_messages[0].get("marker") == marker, (
        f"the side channel must carry this run's marker {marker!r} so messages cannot be "
        f"confused with another run's, got {fast_messages[0]!r}"
    )

    # ---- beats 2-4: the 504 at the CONFIGURED deadline ----------------------------------
    t_before = time.monotonic()
    slow_status, slow_headers, slow_text, slow_elapsed = _http("GET", slow_url, timeout=60.0)
    t_504 = time.monotonic()
    assert slow_status == 504, (
        f"expected 504 from {slow_url} whose integration timeout is {_SLOW_TIMEOUT_MS}ms "
        f"against a backend that takes {_SLEEP_S}s, got {slow_status} after "
        f"{slow_elapsed:.2f}s with body {slow_text[:200]!r} (headers={slow_headers!r})"
    )
    # time semantic: the gateway holds the request open for at least `timeoutInMillis`
    # before it answers INTEGRATION_TIMEOUT, and answers before the backend's own completion.
    assert slow_elapsed >= _SLOW_TIMEOUT_MS / 1000.0, (
        f"expected the 504 to arrive no sooner than the configured {_SLOW_TIMEOUT_MS}ms — an "
        f"immediate 504 is a rejection, not a timeout — got {slow_elapsed:.2f}s"
    )
    assert slow_elapsed < float(_SLEEP_S), (
        f"expected the 504 to arrive BEFORE the backend's {_SLEEP_S}s completion, proving the "
        f"CONFIGURED {_SLOW_TIMEOUT_MS}ms governed rather than the 29s default; got "
        f"{slow_elapsed:.2f}s"
    )
    assert marker not in slow_text, (
        f"effect-absent: a timed-out request must not return the backend's marker {marker!r} "
        f"— got {slow_text[:200]!r}"
    )
    refused = json.loads(slow_text)
    assert refused.get("gw") == f"timeout-{gw_marker}", (
        f"expected the customised INTEGRATION_TIMEOUT gateway response (marker "
        f"'timeout-{gw_marker}') to be served, got {refused!r} — the built-in body means the "
        f"failure was not classified as INTEGRATION_TIMEOUT (INTEGRATION_FAILURE and "
        f"DEFAULT_5XX are also 5xx and would be wrong)"
    )
    assert refused.get("type") == "INTEGRATION_TIMEOUT", (
        f"expected $context.error.responseType to substitute to 'INTEGRATION_TIMEOUT', got "
        f"{refused.get('type')!r} (full body {refused!r})"
    )

    # ---- the point of the check: the backend was NOT cancelled -------------------------
    # At least one completion, not exactly one: whether API Gateway re-invokes the integration
    # after a timeout is not documented.
    slow_messages = _poll_until(
        lambda: [m for m in _drain(sqs, queue_url) if m.get("leg") == "slow"],
        lambda found: len(found) >= 1, timeout_s=_SIDE_CHANNEL_S, interval_s=3.0,
        description=(
            "the timed-out invocation's completion message on the SQS side channel — its "
            "absence would mean API Gateway cancelled the backend, which real AWS does not"
        ),
    )
    t_completion = time.monotonic()
    assert slow_messages[0].get("marker") == marker, (
        f"the timed-out invocation's side-channel message must carry marker {marker!r}, got "
        f"{slow_messages[0]!r}"
    )
    assert t_completion > t_504, (
        f"the backend's completion must be observed AFTER the client already had its 504 "
        f"(504 at +{t_504 - t_before:.2f}s, completion at +{t_completion - t_before:.2f}s) — "
        f"this is what shows the gateway timeout does not stop the work, so a timed-out "
        f"request can still have side effects"
    )

    # ---- beat 5: restore — the IDENTICAL request succeeds at 29000ms --------------------
    _retry_throttled(lambda: ag.update_integration(
        restApiId=api_id, resourceId=resources["slow"], httpMethod="GET",
        patchOperations=[{"op": "replace", "path": "/timeoutInMillis",
                          "value": str(_FAST_TIMEOUT_MS)}]))
    stored = ag.get_integration(restApiId=api_id, resourceId=resources["slow"],
                                httpMethod="GET")
    assert stored.get("timeoutInMillis") == _FAST_TIMEOUT_MS, (
        f"expected GetIntegration to report timeoutInMillis={_FAST_TIMEOUT_MS} after the "
        f"patch, got {stored.get('timeoutInMillis')!r}"
    )
    redeployed = _retry_throttled(
        lambda: ag.create_deployment(restApiId=api_id, stageName=stage))["id"]
    assert redeployed != deployment, (
        f"expected a NEW deployment id for the restore redeploy, got {redeployed!r}"
    )

    def _probe_restored():
        status, _h, text, elapsed = _http("GET", slow_url, timeout=60.0)
        return status, text, elapsed

    r_status, r_text, r_elapsed = _poll_until(
        _probe_restored, lambda r: r[0] == 200, timeout_s=_PROPAGATION_S, interval_s=8.0,
        description=(
            f"GET {slow_url} — the IDENTICAL previously timed-out request — returning 200 once "
            f"timeoutInMillis is {_FAST_TIMEOUT_MS} and the API redeployed"
        ),
    )
    assert marker in r_text, (
        f"restore: the identical request must now reach the backend and return marker "
        f"{marker!r}, got {r_status} after {r_elapsed:.2f}s with body {r_text[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
