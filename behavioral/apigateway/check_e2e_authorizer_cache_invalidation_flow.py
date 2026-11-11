"""e2e-authorizer-cache-invalidation-flow."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-authorizer-cache-invalidation-flow"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]
_TOKEN = "sim2real-fixed-identity-token"
_CONTROL_TOKEN = "sim2real-control-identity-token"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A cached REQUEST authorizer (TTL 300s) runs its Lambda once for repeated same-identity calls,
    and FlushStageAuthorizersCache forces a re-invoke; each invocation reports its identity to an SQS queue."""
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    lambda_ = ctx.client("lambda")
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-authz-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: sqs.delete_queue(QueueUrl=queue_url),
            "AWS.SimpleQueueService.NonExistentQueue",
        )
    )
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    role_name = ctx.unique_name("sim2real-behav-authz-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    inline_policy_name = "sqs-send"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name),
            "NoSuchEntity",
        )
    )
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            ),
            "NoSuchEntity",
        )
    )

    function_name = ctx.unique_name("sim2real-behav-authz-fn-")
    zip_bytes = _build_authorizer_zip(queue_url)

    def _create_function():
        ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
        return lambda_.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=15,
            Tags={"sim2real": CHECK},
        )

    function_arn = _poll_until(
        ctx,
        lambda: _try_create_function(_create_function),
        lambda result: result is not None,
        timeout_s=60,
    )["FunctionArn"]
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: lambda_.delete_function(FunctionName=function_name), "ResourceNotFoundException"
        )
    )

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: apigw.delete_rest_api(restApiId=api_id), "NotFoundException"))

    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{function_arn}/invocations"
    )
    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-behav-authorizer-"),
        type="REQUEST",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=300,
    )["id"]

    lambda_.add_permission(
        FunctionName=function_name,
        StatementId="apigw-invoke-authorizer",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/authorizers/{authorizer_id}",
    )

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    stage_name = "live"
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)

    url = f"{ctx.rest_api_url(api_id, stage_name)}/"
    headers = {"Authorization": _TOKEN}

    _drain_queue(sqs, queue_url)  # clear any stray messages before establishing a baseline

    # First real invocation: IAM role / Lambda permission propagation can lag, so poll for the
    # first success rather than asserting immediately.
    status, _ = _poll_until(
        ctx,
        lambda: _http_get(url, headers),
        lambda result: result[0] == 200,
        timeout_s=180,
    )
    assert status == 200, f"expected 200 from the deployed stage, got {status}"

    first_bodies = _poll_until(
        ctx,
        lambda: _drain_queue(sqs, queue_url),
        lambda bodies: len(bodies) >= 1,
        timeout_s=30,
    )
    assert first_bodies == [_TOKEN], (
        f"expected exactly 1 authorizer invocation for the cold call, got {first_bodies!r}"
    )

    # Second call with the SAME identity source, well within the 300s TTL: cached, no re-invoke.
    status2, _ = _http_get(url, headers)
    assert status2 == 200, f"expected 200 from the deployed stage, got {status2}"

    # Positive control ordered after the cached call: a new identity source must invoke the
    # authorizer, and everything drained up to its invocation must hold no repeat of the cached one.
    status3, _ = _http_get(url, {"Authorization": _CONTROL_TOKEN})
    assert status3 == 200, f"expected 200 from the deployed stage for a new identity, got {status3}"
    drained: list[str] = []

    def _drain_until_control():
        drained.extend(_drain_queue(sqs, queue_url))
        return drained

    _poll_until(ctx, _drain_until_control, lambda bodies: _CONTROL_TOKEN in bodies, timeout_s=30)
    assert drained.count(_TOKEN) == 0, (
        f"expected the cached authorizer result to be reused, got {drained.count(_TOKEN)} new "
        f"invocation(s) for the cached identity before the new identity's invocation"
    )
    assert drained.count(_CONTROL_TOKEN) == 1, (
        f"expected exactly 1 authorizer invocation for the new identity, got {drained.count(_CONTROL_TOKEN)}"
    )

    # Second, independent observable that the cached call produced nothing: the queue's own
    # reported depth, not just what this check's own receive-and-delete drained.
    approx_after_control = int(
        sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"])[
            "Attributes"
        ]["ApproximateNumberOfMessages"]
    )
    assert approx_after_control == 0, (
        f"expected ApproximateNumberOfMessages == 0 confirming no cached-call invocation, "
        f"got {approx_after_control}"
    )

    # FlushStageAuthorizersCache is not instantaneous across every node serving the stage, so a
    # single immediate request can still see the cached decision; replay until the re-invoke lands.
    apigw.flush_stage_authorizers_cache(restApiId=api_id, stageName=stage_name)

    def _probe_post_flush():
        status, _ = _http_get(url, headers)
        assert status == 200, f"expected 200 from the deployed stage, got {status}"
        return _drain_queue(sqs, queue_url).count(_TOKEN)

    post_flush_count = _poll_until(
        ctx,
        _probe_post_flush,
        lambda count: count >= 1,
        timeout_s=150,
    )
    assert post_flush_count == 1, f"expected exactly 1 re-invocation after flush, got {post_flush_count}"

    # DeleteAuthorizer refuses while a method references the authorizer, so the method goes first.
    apigw.delete_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id)

    try:
        apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
        raise AssertionError("expected NotFoundException reading the deleted authorizer")
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "NotFoundException", f"expected NotFoundException, got {err['Code']!r}"
        assert err["Message"] == "Invalid Authorizer identifier specified", (
            f"expected the exact not-found message, got {err['Message']!r}"
        )


def _safe_call(fn, *not_found: str):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in not_found:
            raise


def _try_create_function(create_fn):
    try:
        return create_fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidParameterValueException":
            return None  # IAM role not yet assumable by Lambda; retry
        raise


def _poll_until(ctx, probe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    """Poll every ``interval_s`` until ``predicate`` holds; the deadline is capped by the run budget."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() + interval_s >= deadline:
            raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={last!r}")
        time.sleep(interval_s)


def _http_get(url: str, headers: dict) -> tuple:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _drain_queue(sqs, queue_url: str) -> list[str]:
    bodies: list[str] = []
    for _ in range(5):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        messages = resp.get("Messages", [])
        if not messages:
            break
        for msg in messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg["Body"])
    return bodies


def _build_authorizer_zip(queue_url: str) -> bytes:
    code = f"""
import boto3

_QUEUE_URL = {queue_url!r}

def handler(event, context):
    headers = event.get("headers") or {{}}
    identity = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
    sqs = boto3.client("sqs")
    sqs.send_message(QueueUrl=_QUEUE_URL, MessageBody=identity or "authorizer-invoked")
    return {{
        "principalId": "sim2real-user",
        "policyDocument": {{
            "Version": "2012-10-17",
            "Statement": [{{
                "Action": "execute-api:Invoke",
                "Effect": "Allow",
                "Resource": event["methodArn"],
            }}],
        }},
    }}
"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on first log output; a missing one is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
