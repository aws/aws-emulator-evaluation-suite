"""apigw-integration-lambda-alias-invocation-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-integration-lambda-alias-invocation-positive"
GROUP = "event-propagation"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_MANAGED_TAG_KEY = "sim2real:managed"

_CODE_V1 = '''
import json

def handler(event, context):
    return {"statusCode": 200, "body": json.dumps({"marker": "v1"})}
'''

_CODE_V2 = '''
import json

def handler(event, context):
    return {"statusCode": 200, "body": json.dumps({"marker": "v2"})}
'''


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An API Gateway AWS_PROXY Lambda integration configured with an alias ARN invokes the
    exact function version the alias points to, even after $LATEST has moved on to a newer
    version published after the alias was created."""
    apigw = ctx.client("apigateway")
    lam = ctx.client("lambda")

    role_arn = _create_lambda_role(ctx)
    fn = _create_function(ctx, _CODE_V1, role_arn)
    v1 = lam.publish_version(FunctionName=fn["name"])["Version"]

    lam.update_function_code(FunctionName=fn["name"], ZipFile=_make_zip(_CODE_V2))
    _poll_until(
        lambda: lam.get_function(FunctionName=fn["name"])["Configuration"].get(
            "LastUpdateStatus", "Successful"
        ),
        lambda s: s == "Successful",
        timeout_s=60,
        interval_s=2.0,
        description=f"lambda {fn['name']} code update",
    )
    v2 = lam.publish_version(FunctionName=fn["name"])["Version"]
    assert v1 != v2, f"expected a new version after code update, got v1={v1!r} v2={v2!r}"

    alias_name = "live"
    lam.create_alias(FunctionName=fn["name"], Name=alias_name, FunctionVersion=v1)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=fn["name"], Name=alias_name))

    api_id, resource_id = _create_api_resource(ctx, "test")
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}:{alias_name}/invocations"
        ),
    )
    account_id = fn["arn"].split(":")[4]
    source_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*/*"
    _add_invoke_permission(ctx, fn["name"], source_arn, "sim2real-apigw-invoke", qualifier=alias_name)

    resp = apigw.test_invoke_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert resp["status"] == 200, resp
    body = json.loads(resp["body"])
    assert body["marker"] == "v1", (
        f"alias-qualified integration should resolve the alias's pinned version (v1), "
        f"not the newer $LATEST/v2 code; got marker={body.get('marker')!r} body={body}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _make_zip(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_statements=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_arn))

    if policy_statements:
        pol_name = ctx.unique_name("sim2real-lam-pol-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=pol_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=pol_name))
    return role_arn


def _create_function(ctx, code: str, role_arn: str, timeout: int = 15) -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _make_zip(code)

    def _try_create():
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            return lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags={_MANAGED_TAG_KEY: "true"},
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    resp = _poll_until(
        _try_create,
        lambda r: r is not None,
        timeout_s=60,
        interval_s=3.0,
        description=f"lambda {name} creatable (IAM role propagation)",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"lambda {name} Active",
    )
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_api_resource(ctx, path_part: str) -> tuple[str, str]:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"), tags={_MANAGED_TAG_KEY: "true"}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart=path_part)["id"]
    return api_id, resource_id


def _add_invoke_permission(ctx, function_name: str, source_arn: str, statement_id: str, qualifier: str | None = None) -> None:
    lam = ctx.client("lambda")
    kwargs: dict[str, Any] = {
        "FunctionName": function_name,
        "StatementId": statement_id,
        "Action": "lambda:InvokeFunction",
        "Principal": "apigateway.amazonaws.com",
        "SourceArn": source_arn,
    }
    if qualifier:
        kwargs["Qualifier"] = qualifier
    lam.add_permission(**kwargs)

    def _cleanup():
        rem: dict[str, Any] = {"FunctionName": function_name, "StatementId": statement_id}
        if qualifier:
            rem["Qualifier"] = qualifier
        lam.remove_permission(**rem)

    ctx.on_cleanup(_cleanup)


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
