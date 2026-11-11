"""ruby-async-invoke-onsuccess-and-onfailure-destination-envelope."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ruby-async-invoke-onsuccess-and-onfailure-destination-envelope"
GROUP = "event-propagation"
SERVICES = ["lambda", "sqs"]

_HANDLER = """\
def lambda_handler(event:, context:)
  if event['shouldFail']
    raise "sim2real-ruby-probe-failure:#{event['token']}"
  end
  { 'ok' => true, 'token' => event['token'] }
end
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ruby4.0 async invoke that returns normally delivers a Success invocation record with the
    exact response payload to its OnSuccess destination; one that raises delivers
    RetriesExhausted with the exact error message to its OnFailure destination instead.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html
    """
    success_q = _queue(ctx)
    failure_q = _queue(ctx)
    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": "sqs:SendMessage",
         "Resource": [success_q["arn"], failure_q["arn"]]},
    ])
    fn = _function(ctx, role["arn"], _HANDLER)

    lam = ctx.client("lambda")
    lam.put_function_event_invoke_config(
        FunctionName=fn["name"], MaximumRetryAttempts=0, MaximumEventAgeInSeconds=60,
        DestinationConfig={
            "OnSuccess": {"Destination": success_q["arn"]},
            "OnFailure": {"Destination": failure_q["arn"]},
        },
    )
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function_event_invoke_config(FunctionName=fn["name"]),
        "ResourceNotFoundException"))
    _poll(ctx, lambda: lam.get_function_event_invoke_config(FunctionName=fn["name"]).get("DestinationConfig"),
         lambda d: d is not None, timeout_s=30, interval_s=2, what="the destination config is readable")

    ok_token = ctx.unique_name("ok")
    fail_token = ctx.unique_name("fail")
    _invoke_async(lam, fn["name"], {"shouldFail": False, "token": ok_token})
    _invoke_async(lam, fn["name"], {"shouldFail": True, "token": fail_token})

    sqs = ctx.client("sqs")
    ok_rec = _poll(ctx, lambda: _find(sqs, success_q["url"], ok_token), lambda r: r is not None,
                  timeout_s=90, interval_s=2, what="the OnSuccess destination receives the invocation record")
    assert ok_rec["version"] == "1.0", f"invocation record version was {ok_rec['version']!r}"
    assert ok_rec["requestContext"]["condition"] == "Success", (
        f"OnSuccess record condition was {ok_rec['requestContext']['condition']!r}")
    assert ok_rec["requestPayload"] == {"shouldFail": False, "token": ok_token}, (
        f"requestPayload was {ok_rec['requestPayload']!r}")
    assert ok_rec["responsePayload"] == {"ok": True, "token": ok_token}, (
        f"responsePayload must be the handler's exact return value, got {ok_rec['responsePayload']!r}")
    assert ok_rec["responseContext"]["statusCode"] == 200, (
        f"responseContext.statusCode was {ok_rec['responseContext']['statusCode']!r}")

    fail_rec = _poll(ctx, lambda: _find(sqs, failure_q["url"], fail_token), lambda r: r is not None,
                     timeout_s=90, interval_s=2, what="the OnFailure destination receives the invocation record")
    assert fail_rec["requestContext"]["condition"] == "RetriesExhausted", (
        f"OnFailure record condition was {fail_rec['requestContext']['condition']!r}")
    assert fail_rec["requestPayload"] == {"shouldFail": True, "token": fail_token}, (
        f"requestPayload was {fail_rec['requestPayload']!r}")
    assert fail_rec["responsePayload"]["errorMessage"] == f"sim2real-ruby-probe-failure:{fail_token}", (
        f"errorMessage was {fail_rec['responsePayload'].get('errorMessage')!r}")
    assert fail_rec["responsePayload"].get("errorType") == "Function<RuntimeError>", (
        f"the ruby4.0 runtime reports a function-raised error's errorType as "
        f"'Function<RuntimeError>', got {fail_rec['responsePayload'].get('errorType')!r}")
    assert isinstance(fail_rec["responsePayload"].get("stackTrace"), list) and (
        fail_rec["responsePayload"]["stackTrace"]), (
        f"the ruby4.0 runtime's error payload must carry a non-empty 'stackTrace' list, got "
        f"{fail_rec['responsePayload'].get('stackTrace')!r}")
    assert fail_rec["responseContext"].get("functionError") == "Unhandled", (
        f"responseContext.functionError was {fail_rec['responseContext'].get('functionError')!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, timeout_s, interval_s, what):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _zip(code: str, filename: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _execution_role(ctx, statements) -> dict:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"), "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"]}


def _function(ctx, role_arn, code, *, timeout=10, memory=128) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": "ruby4.0", "Handler": "lambda_function.lambda_handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code, "lambda_function.rb")},
              "Timeout": timeout, "MemorySize": memory, "Tags": {"sim2real": CHECK}}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidParameterValueException" and "cannot be assumed" in err.get("Message", ""):
                return None
            raise

    out = _poll(ctx, create, lambda r: r is not None, timeout_s=90, interval_s=2,
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    conf = _poll(ctx, lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"), timeout_s=90, interval_s=2,
                 what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    assert conf["Runtime"] == "ruby4.0", f"expected Runtime=ruby4.0, got {conf.get('Runtime')!r}"
    return {"name": name, "arn": out["FunctionArn"]}


def _invoke_async(lam, name, payload):
    resp = lam.invoke(FunctionName=name, InvocationType="Event", Payload=json.dumps(payload).encode())
    assert resp["StatusCode"] == 202, f"async invoke returned StatusCode {resp['StatusCode']!r}"


def _queue(ctx) -> dict:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-xsvc-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url), "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _find(sqs, url, token):
    """The one invocation record among the queue's messages whose requestPayload carries token."""
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
    for m in resp.get("Messages", []):
        rec = json.loads(m["Body"])
        if rec.get("requestPayload", {}).get("token") == token:
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            return rec
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
