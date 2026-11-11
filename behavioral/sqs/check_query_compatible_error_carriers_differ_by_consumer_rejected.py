"""query-compatible-error-carriers-differ-by-consumer-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

import urllib3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-compatible-error-carriers-differ-by-consumer-rejected"
GROUP = 'multi-sdk-error-vocabulary-rejected'
SERVICES = ['sqs']

_LEGACY_ABSENT = 'AWS.SimpleQueueService.NonExistentQueue'
_MODERN_ABSENT = 'QueueDoesNotExist'
_JS_SOURCE = r'''
import {SQSClient, GetQueueUrlCommand, ReceiveMessageCommand, SendMessageCommand,
        QueueDoesNotExist} from "@aws-sdk/client-sqs";
import pj from "@aws-sdk/client-sqs/package.json" with {type: "json"};

export const handler = async (ev) => {
  const client = new SQSClient({region: ev.region});
  const out = {sdkVersion: pj.version, node: process.version};
  const probe = async (key, cmd) => {
    try {
      const r = await client.send(cmd);
      out[key] = {ok: true, QueueUrl: r.QueueUrl ?? null};
    } catch (e) {
      out[key] = {ok: false, ctor: e.constructor.name, name: e.name, message: e.message,
                  isQueueDoesNotExist: e instanceof QueueDoesNotExist,
                  httpStatusCode: e.$metadata?.httpStatusCode ?? null,
                  requestId: e.$metadata?.requestId ?? null};
    }
  };
  await probe("absentGetUrl", new GetQueueUrlCommand({QueueName: ev.absentName}));
  await probe("absentReceive", new ReceiveMessageCommand({QueueUrl: ev.absentUrl}));
  await probe("badDelay", new SendMessageCommand(
      {QueueUrl: ev.presentUrl, MessageBody: "x", DelaySeconds: 901}));
  await probe("control", new GetQueueUrlCommand({QueueName: ev.presentName}));
  return out;
};
'''


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_active(lam, fn_name: str, timeout_s: float, ctx=None) -> None:
    """Poll until the function's State is Active, failing if it never gets there."""
    deadline = time.monotonic() + timeout_s
    state = None
    while True:
        state = lam.get_function_configuration(FunctionName=fn_name).get("State")
        if state == "Active":
            return
        if state in ("Pending", None) and time.monotonic() >= deadline and ctx is not None and _budget_spent(ctx):
            raise TimeoutError(f"function {fn_name!r} becoming Active: the run budget ended first; not graded")
        assert state in ("Pending", None) and time.monotonic() < deadline, (
            f"function {fn_name!r} did not become Active (State {state!r})")
        time.sleep(1.0)


def _teardown_function(ctx, lam, logs, fn_name: str) -> None:
    """Delete a function and its log group, verifying the group is gone.

    Lambda creates the group asynchronously on first invocation, so a delete registered at
    create time can run before the group exists."""
    lam.delete_function(FunctionName=fn_name)
    group = f"/aws/lambda/{fn_name}"
    deadline = time.time() + _budget_s(ctx, 120.0)
    while time.time() < deadline:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        described = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        if not [g for g in described if g["logGroupName"] == group]:
            # Gone must hold over a fixed 5 s window (3 samples): a late first-invocation
            # create would bring the group back.
            for _ in range(2):
                time.sleep(2.5)
                described = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
                if [g for g in described if g["logGroupName"] == group]:
                    break
            else:
                return
        time.sleep(1.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"log group {group!r} staying deleted: the run budget ended first; not graded")
    raise AssertionError(f"log group {group!r} still present after delete_log_group")


def _unless_gone(fn, *codes):
    """A backup cleanup the in-band teardown may already have done: only *codes* (the resource's
    own not-found) count as done; any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _error(fn):
    """Call fn(); return the botocore ClientError, raising if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"real AWS refuses this call; the target returned {result!r}")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """One SQS refusal carries an AWS-Query code (x-amzn-query-error header) and a Smithy code (body
    __type): botocore reports the Query code, JS v3 the modeled Smithy one, and for an unmodeled
    error (DelaySeconds=901) JS falls back to the header so the two SDKs agree.
    """
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    base = ctx.unique_name("sim2real-behav-h1sqs-")
    queue_name = base + "-q"
    absent_name = base + "-absent"

    # botocore sends the awsQueryCompatible opt-in header on every SQS request.
    sent_headers = {}
    sqs.meta.events.register(
        "before-send.sqs.*",
        lambda request, **_kw: sent_headers.update(
            {k.lower(): (v.decode() if isinstance(v, bytes) else v)
             for k, v in request.headers.items()}))

    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real-check": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: sqs.delete_queue(QueueUrl=queue_url),
        "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"))
    absent_url = queue_url.rsplit("/", 1)[0] + "/" + absent_name

    assert sent_headers.get("x-amzn-query-mode") == "true", (
        "botocore did not send x-amzn-query-mode on an SQS request; headers were "
        f"{sorted(sent_headers)!r} -- the awsQueryCompatible opt-in is the request-side half "
        "of this check")
    assert sent_headers.get("content-type") == "application/x-amz-json-1.0", (
        f"botocore's SQS content-type was {sent_headers.get('content-type')!r}, so this is no "
        "longer the awsJson1.0 wire the check reasons about")

    # The nodejs22.x runtime bundles the AWS SDK for JavaScript v3, so no packaging is needed.
    role_name = base + "-role"
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sqs",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["sqs:GetQueueUrl", "sqs:ReceiveMessage",
                                      "sqs:SendMessage"],
                           "Resource": f"arn:aws:sqs:{ctx.region}:{account}:{base}-*"},
                          {"Effect": "Allow",
                           "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                      "logs:PutLogEvents"],
                           "Resource": "*"}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sqs"))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("index.mjs", (2020, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        zf.writestr(info, _JS_SOURCE)

    fn_name = base + "-js"
    # A fresh role is not yet assumable by Lambda; retry only InvalidParameterValueException.
    created = None
    deadline = time.time() + _budget_s(ctx, 120.0)
    while created is None:
        try:
            created = lam.create_function(
                FunctionName=fn_name, Runtime="nodejs22.x", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": buf.getvalue()},
                Timeout=60, MemorySize=256, Tags={"sim2real-check": CHECK})
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidParameterValueException" and time.time() >= deadline and _budget_spent(ctx):
                raise TimeoutError("create_function accepting the fresh role: the run budget ended first; "
                                   "not graded") from exc
            assert code == "InvalidParameterValueException" and time.time() < deadline, (
                f"create_function failed with {code!r}: {exc}")
            time.sleep(2.0)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{fn_name}"),
        "ResourceNotFoundException"))
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: lam.delete_function(FunctionName=fn_name), "ResourceNotFoundException"))
    _wait_active(lam, fn_name, _budget_s(ctx, 120.0), ctx=ctx)
    assert created["Runtime"] == "nodejs22.x", f"runtime is {created['Runtime']!r}"

    payload = json.dumps({"region": ctx.region, "absentName": absent_name,
                          "absentUrl": absent_url, "presentUrl": queue_url,
                          "presentName": queue_name}).encode()
    # Retry until the positive control succeeds: the role's SQS grant may not have propagated yet.
    js = None
    deadline = time.time() + _budget_s(ctx, 180.0)
    while True:
        invoked = lam.invoke(FunctionName=fn_name, Payload=payload, LogType="Tail")
        assert invoked.get("FunctionError") is None, (
            f"the JS v3 consumer failed: {invoked['Payload'].read()!r}")
        js = json.loads(invoked["Payload"].read())
        if js.get("control", {}).get("ok") is True or time.time() > deadline:
            break
        time.sleep(2.0)
    if js["control"].get("ok") is not True and _budget_spent(ctx):
        raise TimeoutError("the JS consumer's role becoming effective: the run budget ended first; not graded")
    assert js["control"].get("ok") is True, (
        f"the JS consumer's role never became effective: {js!r}")

    js_version = js["sdkVersion"]
    assert js_version.startswith("3."), (
        f"the nodejs22.x runtime bundled @aws-sdk/client-sqs {js_version!r}, not a v3")

    raw_creds = sqs._request_signer._credentials
    frozen = (raw_creds.get_frozen_credentials()
              if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    endpoint = sqs.meta.endpoint_url
    pool = urllib3.PoolManager()

    def raw(target: str, body: dict, *, query_mode: bool):
        headers = {"content-type": "application/x-amz-json-1.0",
                   "x-amz-target": f"AmazonSQS.{target}"}
        if query_mode:
            headers["x-amzn-query-mode"] = "true"
        data = json.dumps(body).encode()
        req = AWSRequest(method="POST", url=endpoint, data=data, headers=headers)
        SigV4Auth(frozen, sqs.meta.service_model.signing_name, ctx.region).add_auth(req)
        resp = pool.request("POST", endpoint, body=data,
                            headers=dict(req.headers.items()), retries=False)
        return (resp.status,
                {k.lower(): v for k, v in resp.headers.items()},
                json.loads(resp.data) if resp.data else {})

    # botocore reports the AWS-Query code, which only the response header carries.
    exc = _error(lambda: sqs.get_queue_url(QueueName=absent_name))
    boto_err = exc.response["Error"]
    assert boto_err["Code"] == _LEGACY_ABSENT, (
        f"botocore reported Error.Code {boto_err['Code']!r}, expected {_LEGACY_ABSENT!r} -- "
        "the legacy AWS-Query code, which botocore can only get from x-amzn-query-error")
    assert boto_err["Type"] == "Sender", (
        f"botocore reported Error.Type {boto_err.get('Type')!r}, expected 'Sender' -- the "
        "second field that header carries")
    assert boto_err["QueryErrorCode"] == _MODERN_ABSENT, (
        f"botocore reported Error.QueryErrorCode {boto_err.get('QueryErrorCode')!r}, expected "
        f"{_MODERN_ABSENT!r} -- botocore keeps the modern code here and puts the legacy one in "
        "Error.Code, so BOTH carriers must be present for this field to exist")
    assert type(exc).__name__ == _MODERN_ABSENT, (
        f"botocore raised {type(exc).__name__!r}; the modeled class is named after the MODERN "
        f"code {_MODERN_ABSENT!r} while Error.Code is the legacy one -- one response, two "
        "vocabularies, inside a single SDK")
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, (
        f"status was {exc.response['ResponseMetadata']['HTTPStatusCode']!r}")

    # Raw response: both carriers present, and no x-amzn-errortype header.
    status, headers, body = raw("GetQueueUrl", {"QueueName": absent_name}, query_mode=True)
    assert status == 400, f"raw GetQueueUrl on an absent queue gave {status!r}: {body!r}"
    assert headers.get("x-amzn-query-error") == f"{_LEGACY_ABSENT};Sender", (
        f"x-amzn-query-error was {headers.get('x-amzn-query-error')!r}, expected "
        f"'{_LEGACY_ABSENT};Sender' -- this exact header is in 0 of 5,349 wire fixtures")
    assert body.get("__type") == f"com.amazonaws.sqs#{_MODERN_ABSENT}", (
        f"body __type was {body.get('__type')!r}, expected the #-namespaced modern code "
        f"'com.amazonaws.sqs#{_MODERN_ABSENT}'")
    assert "x-amzn-errortype" not in headers, (
        f"SQS sent an x-amzn-errortype header ({headers.get('x-amzn-errortype')!r}); measured, "
        "it does not -- the modern code travels only in the body for this protocol")

    # SQS sends x-amzn-query-error even when the request does not opt in.
    status, headers_off, body_off = raw(
        "GetQueueUrl", {"QueueName": absent_name}, query_mode=False)
    assert status == 400, f"raw call without query-mode gave {status!r}: {body_off!r}"
    assert headers_off.get("x-amzn-query-error") == f"{_LEGACY_ABSENT};Sender", (
        "SQS omitted x-amzn-query-error when the request carried no x-amzn-query-mode; "
        f"measured, it sends it regardless. headers {headers_off!r}")
    assert body_off.get("__type") == body.get("__type"), (
        f"the body code changed with the opt-in: {body_off.get('__type')!r} vs "
        f"{body.get('__type')!r}")

    # JS v3 reads the Smithy code from the same response.
    got = js["absentGetUrl"]
    assert got["ok"] is False, f"the JS consumer resolved an absent queue: {got!r}"
    assert got["ctor"] == _MODERN_ABSENT, (
        f"JS v3 {js_version} constructed {got['ctor']!r}, expected {_MODERN_ABSENT!r} -- the "
        "constructor, so a generic error carrying a hand-set `name` cannot pass")
    assert got["name"] == _MODERN_ABSENT, (
        f"JS v3 {js_version} reported name {got['name']!r}, expected {_MODERN_ABSENT!r}")
    assert got["isQueueDoesNotExist"] is True, (
        f"JS v3 {js_version} did not produce its MODELED QueueDoesNotExist: {got!r} -- a "
        "`catch (e) {{ if (e instanceof QueueDoesNotExist) }}` branch would be dead code")
    assert got["httpStatusCode"] == 400, f"JS saw status {got['httpStatusCode']!r}"
    assert isinstance(got["requestId"], str) and got["requestId"], (
        f"JS found no request id: {got!r}")

    # The two SDKs report different codes for one response, and both are correct.
    assert boto_err["Code"] != got["name"], (
        f"botocore and JS v3 {js_version} both reported {got['name']!r}; real AWS makes them "
        f"differ ({_LEGACY_ABSENT!r} vs {_MODERN_ABSENT!r}) because the response carries two "
        "vocabularies. One error code means one carrier was dropped")
    assert boto_err["Message"] == got["message"] == body["message"] == \
        "The specified queue does not exist.", (
        f"the three readers disagree on the message: botocore {boto_err['Message']!r}, "
        f"JS {got['message']!r}, raw {body.get('message')!r}")

    # A second operation shows the same split.
    exc2 = _error(lambda: sqs.receive_message(QueueUrl=absent_url))
    assert exc2.response["Error"]["Code"] == _LEGACY_ABSENT, (
        f"ReceiveMessage on an absent queue gave botocore "
        f"{exc2.response['Error']['Code']!r}, expected {_LEGACY_ABSENT!r}")
    recv = js["absentReceive"]
    assert recv["name"] == _MODERN_ABSENT, (
        f"JS ReceiveMessage on an absent queue gave {recv['name']!r}, expected "
        f"{_MODERN_ABSENT!r}")
    assert recv["isQueueDoesNotExist"] is True, f"JS ReceiveMessage error untyped: {recv!r}"

    # InvalidParameterValueException is not a modeled SQS shape, so JS v3 falls back to the
    # x-amzn-query-error code and agrees with botocore. Its __type namespace is coral, not sqs.
    exc3 = _error(lambda: sqs.send_message(
        QueueUrl=queue_url, MessageBody="x", DelaySeconds=901))
    boto3_err = exc3.response["Error"]
    assert boto3_err["Code"] == "InvalidParameterValue", (
        f"DelaySeconds=901 gave botocore Error.Code {boto3_err['Code']!r}, expected the legacy "
        "'InvalidParameterValue'")
    assert boto3_err["QueryErrorCode"] == "InvalidParameterValueException", (
        f"DelaySeconds=901 gave QueryErrorCode {boto3_err.get('QueryErrorCode')!r}, expected "
        "'InvalidParameterValueException' -- the modern code, which differs from the legacy "
        "one by more than a namespace")
    assert boto3_err["Code"] != _LEGACY_ABSENT, "two distinct refusals collapsed to one code"
    status, headers3, body3 = raw(
        "SendMessage", {"QueueUrl": queue_url, "MessageBody": "x", "DelaySeconds": 901},
        query_mode=True)
    assert status == 400, f"raw DelaySeconds=901 gave {status!r}: {body3!r}"
    assert headers3.get("x-amzn-query-error") == "InvalidParameterValue;Sender", (
        f"x-amzn-query-error was {headers3.get('x-amzn-query-error')!r}")
    assert body3.get("__type") == "com.amazon.coral.service#InvalidParameterValueException", (
        f"body __type was {body3.get('__type')!r}; real SQS uses the com.amazon.coral.service "
        "namespace for this one and com.amazonaws.sqs for QueueDoesNotExist, so a single "
        "hardcoded namespace prefix fails here")
    delay = js["badDelay"]
    assert delay["name"] == "InvalidParameterValue", (
        f"JS v3 {js_version} reported name {delay['name']!r} for DelaySeconds=901, expected the "
        "LEGACY 'InvalidParameterValue' -- with no modeled class for "
        "'InvalidParameterValueException' it falls back to x-amzn-query-error, so an emulator "
        "that omits that header hands JS the modern code here and diverges from botocore")
    assert delay["ctor"] == "SQSServiceException", (
        f"JS constructed {delay['ctor']!r} for DelaySeconds=901, expected the generic "
        "'SQSServiceException' -- the modern code is unmodeled, which is exactly why the "
        "header fallback fires")
    assert delay["name"] == boto3_err["Code"], (
        f"the two SDKs disagreed on the second refusal (botocore {boto3_err['Code']!r} vs JS "
        f"{delay['name']!r}); measured, they CONVERGE here on the legacy code, and #5 is where "
        "they diverge -- one carrier alone cannot produce both outcomes")
    assert delay["isQueueDoesNotExist"] is False, (
        f"JS typed a DelaySeconds validation error as QueueDoesNotExist: {delay!r}")

    # Positive control: all three consumers resolve the real queue.
    resolved = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    assert resolved == queue_url, f"botocore resolved {resolved!r}, created {queue_url!r}"
    control = js["control"]
    assert control["ok"] is True and control["QueueUrl"] == queue_url, (
        f"the JS consumer could not resolve the real queue: {control!r}")
    status, _headers, body4 = raw("GetQueueUrl", {"QueueName": queue_name}, query_mode=True)
    assert status == 200 and body4["QueueUrl"] == queue_url, (
        f"the raw consumer resolved {status!r} {body4!r}, expected {queue_url!r}")

    # The refusals created no queues.
    found = []
    token = None
    while True:
        page = sqs.list_queues(QueueNamePrefix=base,
                               **({"NextToken": token} if token else {}))
        found.extend(page.get("QueueUrls", []))
        token = page.get("NextToken")
        if not token:
            break
    assert found == [queue_url], (
        f"the refusals left queues behind or the control queue vanished: {found!r}, expected "
        f"exactly [{queue_url!r}]")

    _teardown_function(ctx, lam, logs, fn_name)
    sqs.delete_queue(QueueUrl=queue_url)
    deadline = time.time() + _budget_s(ctx, 120.0)
    gone = None
    while time.time() < deadline:
        try:
            sqs.get_queue_url(QueueName=queue_name)
        except ClientError as exc4:
            gone = exc4.response.get("Error", {}).get("Code")
            break
        time.sleep(1.0)
    if gone is None and _budget_spent(ctx):
        raise TimeoutError("GetQueueUrl refusing the deleted queue: the run budget ended first; not graded")
    assert gone == _LEGACY_ABSENT, (
        f"the queue was still resolvable after delete_queue (last code {gone!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
