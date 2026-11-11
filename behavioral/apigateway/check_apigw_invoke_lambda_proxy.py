"""apigw-invoke-lambda-proxy."""
from __future__ import annotations

import io
import json
import time
import zipfile
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-invoke-lambda-proxy"
GROUP = 'invoke'
SERVICES = ['apigateway']


def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestInvokeMethod on an AWS_PROXY method runs the Lambda integration server-side, with no
    deployment, and returns the function's proxy response body and status 200."""
    ag = ctx.client("apigateway")
    handler_code = """
import json
def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "marker": "rest-lambda-proxy-ok",
            "path": event.get("path"),
            "httpMethod": event.get("httpMethod"),
        }),
    }
"""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-lambda-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )
    role_arn = role["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ],
            }
        ),
    )

    def _delete_role():
        try:
            for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_delete_role)

    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)

    kwargs = {
        "FunctionName": fn_name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": 30,
        "MemorySize": 128,
        "Tags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    deadline = time.monotonic() + 40
    last_err = None
    fn_arn = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            fn_arn = resp["FunctionArn"]
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
            break
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    if fn_arn is None:
        raise last_err or RuntimeError(f"failed to create lambda {fn_name}")

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if lam.get_function_configuration(FunctionName=fn_name).get("State") == "Active":
            break
        time.sleep(2)
    fn = {"name": fn_name, "arn": fn_arn}

    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)
    resource = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="hello")
    resource_id = resource["id"]

    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"{fn['arn']}/invocations"
    )
    ag.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=uri,
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    source_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*"
    try:
        lam.add_permission(
            FunctionName=fn["name"],
            StatementId="apigw-invoke",
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )
    except ClientError as e:
        if "ResourceConflictException" not in str(e) and "already exists" not in str(e).lower():
            raise

    try:
        lam.get_waiter("function_active_v2").wait(
            FunctionName=fn["name"], WaiterConfig={"Delay": 2, "MaxAttempts": 60}
        )
    except Exception:
        left = ctx.time_left()
        deadline = time.monotonic() + (120 if left is None else max(1.0, min(120, left - 5)))
        while time.monotonic() < deadline:
            if lam.get_function(FunctionName=fn["name"])["Configuration"].get("State") == "Active":
                break
            time.sleep(2)

    status, body = None, ""
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        resp = ag.test_invoke_method(
            restApiId=api_id, resourceId=resource_id, httpMethod="GET"
        )
        status, body = resp.get("status"), resp.get("body") or ""
        if status == 200:
            break
        time.sleep(3)

    assert status == 200, (
        f"expected 200 from test_invoke_method, got {status}: {body}\n"
        f"APIGW LOG:\n{resp.get('log')}"
    )
    data = json.loads(body)
    assert data.get("marker") == "rest-lambda-proxy-ok", f"unexpected proxy body: {data}"


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
