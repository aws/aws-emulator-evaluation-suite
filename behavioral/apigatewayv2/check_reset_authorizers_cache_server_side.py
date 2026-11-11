"""reset-authorizers-cache-server-side."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags

CHECK = "reset-authorizers-cache-server-side"
GROUP = "server-side"
SERVICES = ["apigatewayv2"]

_LAMBDA_CODE = """
import json, os, uuid
import boto3

TABLE_NAME = os.environ.get("TABLE_NAME", "")
_table = boto3.resource("dynamodb").Table(TABLE_NAME) if TABLE_NAME else None


def handler(event, context):
    if event.get("type") == "REQUEST":
        if _table is not None:
            _table.put_item(Item={"id": str(uuid.uuid4())})
        return {"isAuthorized": True}
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({"ok": True}),
    }
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """ResetAuthorizersCache must invalidate a stage's cached Lambda-authorizer
    decision server-side: a cached identity source is not re-authorized until
    the cache is reset, at which point the next call re-invokes the authorizer."""
    apigw = ctx.client("apigatewayv2")
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    table_name = ctx.unique_name("sim2real-authz-invocations-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    role_name = ctx.unique_name("sim2real-authz-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
    )
    inline_policy_name = "sim2real-ddb-put"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "dynamodb:PutItem",
                        "Resource": f"arn:aws:dynamodb:{ctx.region}:{account_id}:table/{table_name}",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name)
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", _LAMBDA_CODE)
    zip_bytes = buf.getvalue()

    function_name = ctx.unique_name("sim2real-combo-fn-")
    function_arn = _create_function_with_retry(
        lam,
        function_name=function_name,
        role_arn=role_arn,
        zip_bytes=zip_bytes,
        table_name=table_name,
        check_name=CHECK,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    api = apigw.create_api(
        Name=ctx.unique_name("sim2real-http-"),
        ProtocolType="HTTP",
        Tags={"sim2real-check": CHECK},
    )
    api_id = api["ApiId"]
    api_endpoint = api["ApiEndpoint"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    lam.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*",
    )

    authorizer = apigw.create_authorizer(
        ApiId=api_id,
        AuthorizerType="REQUEST",
        IdentitySource=["$request.header.Authorization"],
        Name=ctx.unique_name("sim2real-authorizer-"),
        AuthorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{function_arn}/invocations"
        ),
        AuthorizerPayloadFormatVersion="2.0",
        EnableSimpleResponses=True,
        AuthorizerResultTtlInSeconds=300,
    )
    authorizer_id = authorizer["AuthorizerId"]

    integration = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=function_arn,
        PayloadFormatVersion="2.0",
        IntegrationMethod="POST",
    )
    integration_id = integration["IntegrationId"]

    apigw.create_route(
        ApiId=api_id,
        RouteKey="GET /cache-test",
        AuthorizationType="CUSTOM",
        AuthorizerId=authorizer_id,
        Target=f"integrations/{integration_id}",
    )

    deployment = apigw.create_deployment(ApiId=api_id)
    deployment_id = deployment["DeploymentId"]
    _poll_until(
        lambda: apigw.get_deployment(ApiId=api_id, DeploymentId=deployment_id),
        lambda d: d["DeploymentStatus"] == "DEPLOYED",
        timeout_s=60,
    )

    stage_name = "dev"
    apigw.create_stage(ApiId=api_id, StageName=stage_name, DeploymentId=deployment_id)

    url = f"{api_endpoint}/{stage_name}/cache-test"
    headers = {"Authorization": "sim2real-cache-token"}

    # Call #1: authorizer must run and record one invocation. Time this leg
    # end-to-end so the negative below can be held for a real multiple of it,
    # instead of an arbitrary fixed sleep.
    t0 = time.monotonic()
    _poll_invoke_until_ok(ctx, url, headers, timeout_s=60)
    _poll_until(lambda: _count(ddb, table_name), lambda c: c == 1, timeout_s=20)
    cold_invoke_latency_s = time.monotonic() - t0

    # Call #2 with the SAME identity source: cached decision must be reused,
    # the authorizer must NOT run again. Hold the negative for >=3x the
    # measured cold-invoke latency (never a bare sleep) and read repeatedly
    # so a late write is caught the instant it lands, not only at one point.
    status, _ = _invoke(ctx, url, headers)
    assert status == 200, f"expected 200 on a cache-hit invoke, got {status}"
    _assert_count_holds(
        ddb, table_name,
        expected=1,
        hold_s=max(9.0, 3 * cold_invoke_latency_s),
        interval_s=1.0,
        message="authorizer ran again for a cached identity source",
    )

    # Invalidate the cache server-side.
    apigw.reset_authorizers_cache(ApiId=api_id, StageName=stage_name)

    # Call #3 with the SAME identity source: the cache was reset, so the
    # authorizer must run again. Reissue the request repeatedly (bounded)
    # since cache invalidation may take a few seconds to propagate across
    # the service fleet.
    _poll_reinvoke_until(ctx, url, headers, ddb, table_name, timeout_s=90)
    final_count = _count(ddb, table_name)
    assert final_count == 2, f"expected exactly 2 invocations after cache reset, got {final_count}"


def _poll_until(probe, predicate, *, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _create_function_with_retry(lam, *, function_name, role_arn, zip_bytes, table_name, check_name):
    deadline = time.monotonic() + 60
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=15,
                Environment={"Variables": {"TABLE_NAME": table_name}},
                Tags={"sim2real-check": check_name},
            )
            return resp["FunctionArn"]
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"lambda role never propagated: {last_exc}")


def _invoke(ctx, url, headers, timeout=10):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, headers={**(headers), **_route}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


def _poll_invoke_until_ok(ctx, url, headers, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            status, body = _invoke(ctx, url, headers)
            if status == 200:
                return status, body
            last_err = AssertionError(f"unexpected status {status}: {body!r}")
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            last_err = exc
        time.sleep(interval_s)
    raise AssertionError(f"invoke never succeeded within {timeout_s}s: {last_err}")


def _poll_reinvoke_until(ctx, url, headers, ddb, table_name, *, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_count = None
    while time.monotonic() < deadline:
        try:
            status, _ = _invoke(ctx, url, headers)
            assert status == 200, f"unexpected status {status}"
        except (urllib.error.HTTPError, urllib.error.URLError):
            pass
        last_count = _count(ddb, table_name)
        if last_count == 2:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"authorizer never re-invoked after ResetAuthorizersCache within "
        f"{timeout_s}s (last count={last_count!r})"
    )


def _count(ddb, table_name):
    return ddb.scan(TableName=table_name, Select="COUNT", ConsistentRead=True)["Count"]


def _assert_count_holds(ddb, table_name, *, expected, hold_s, interval_s, message):
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        actual = _count(ddb, table_name)
        assert actual == expected, f"{message} (expected={expected}, actual={actual})"
        time.sleep(interval_s)



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
