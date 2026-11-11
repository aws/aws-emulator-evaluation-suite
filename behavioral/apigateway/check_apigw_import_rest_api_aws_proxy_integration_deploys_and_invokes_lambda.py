"""apigw-import-rest-api-aws-proxy-integration-deploys-and-invokes-lambda."""
from __future__ import annotations

import io
import json
import random
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-import-rest-api-aws-proxy-integration-deploys-and-invokes-lambda"
GROUP = "import-export"
SERVICES = ["apigateway"]

_HANDLER = """
import json
def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"marker": "sim2real-imported-proxy-ok", "path": event.get("path")}),
    }
"""


def _http(method, url, body=None, headers=None, timeout_s=20):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - fixed https
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read().decode()


def _poll_http(url, predicate, *, method="GET", body=None, headers=None, timeout_s=90.0,
                interval_s=3.0, description="response"):
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, text = _http(method, url, body=body, headers=headers)
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; last=({status}, {text!r})"
            )
        time.sleep(interval_s)


def _lambda_zip(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)
    return buf.getvalue()


def _create_function_with_retry(lam, retries=12, delay_s=5.0, **kwargs):
    last_err = None
    for _ in range(retries):
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_err = exc
            time.sleep(delay_s)
    raise last_err


def _wait_active(lam, fn_name, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while True:
        state = lam.get_function_configuration(FunctionName=fn_name).get("State")
        if state == "Active":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"Lambda never became Active, last state={state!r}")
        time.sleep(2)


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    DeleteRestApi's account-wide burst is small: a 4th consecutive delete within a couple of
    seconds throttles.
    """
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(5.0, 0.5 * (2**attempt)) + random.uniform(0, 0.3))


def _openapi_doc(title, fn_arn, region):
    """An OpenAPI 3 document whose single path declares an aws_proxy integration at a
    concrete (non-pseudo-parameter) Lambda ARN."""
    uri = f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{fn_arn}/invocations"
    return json.dumps(
        {
            "openapi": "3.0.1",
            "info": {"title": title, "version": "1.0"},
            "paths": {
                "/hello": {
                    "get": {
                        "responses": {"200": {"description": "ok"}},
                        "x-amazon-apigateway-integration": {
                            "type": "aws_proxy",
                            "httpMethod": "POST",
                            "uri": uri,
                            "payloadFormatVersion": "1.0",
                        },
                    }
                }
            },
        }
    ).encode()


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "concern:e2e",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """ImportRestApi turns an OpenAPI aws_proxy integration into an AWS_PROXY method whose deployed
    GET /hello invokes the Lambda and returns its body with the proxied path."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    ag = ctx.client("apigateway")

    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    fn_name = ctx.unique_name("sim2real-behav-import-fn-")
    created = _create_function_with_retry(
        lam,
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": _lambda_zip(_HANDLER)},
        Timeout=15,
        Tags={"sim2real:managed": "true"},
    )
    fn_arn = created["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_active(lam, fn_name)

    title = ctx.unique_name("sim2real-behav-import-")
    document = _openapi_doc(title, fn_arn, ctx.region)

    imported = ag.import_rest_api(
        body=document, parameters={"endpointConfigurationTypes": "REGIONAL"}
    )
    api_id = imported["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    ag.tag_resource(
        resourceArn=f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}",
        tags={"sim2real:managed": "true"},
    )
    assert imported.get("name") == title, (
        f"the imported API must be named from the document's info.title, got "
        f"{imported.get('name')!r}"
    )

    resources = ag.get_resources(restApiId=api_id)["items"]
    hello = next((r for r in resources if r.get("path") == "/hello"), None)
    assert hello is not None, f"expected a /hello resource from the import, got paths {[r.get('path') for r in resources]!r}"
    integration = ag.get_integration(restApiId=api_id, resourceId=hello["id"], httpMethod="GET")
    assert integration["type"] == "AWS_PROXY", (
        f"expected the imported integration type to be AWS_PROXY, got {integration.get('type')!r}"
    )
    assert integration["uri"].endswith(f"{fn_arn}/invocations"), (
        f"expected the imported integration uri to reference the Lambda ARN, got "
        f"{integration.get('uri')!r}"
    )

    account_id = ctx.account
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*",
    )
    ag.create_deployment(restApiId=api_id, stageName="test")

    url = f"{ctx.rest_api_url(api_id, 'test')}/hello"
    status, _headers, text = _poll_http(
        url, lambda s, h, t: s == 200, description="GET /hello on the imported aws_proxy route"
    )
    assert status == 200, f"expected 200 from the imported route, got {status}: {text!r}"
    payload = json.loads(text)
    assert payload.get("marker") == "sim2real-imported-proxy-ok", (
        f"expected the real Lambda's body, got {payload!r}"
    )
    assert payload.get("path") == "/hello", f"expected path '/hello' in the proxy event, got {payload!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
