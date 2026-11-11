"""apigw-integration-lambda-alias-mismatch-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigw-integration-lambda-alias-mismatch-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_CODE = '''
import json

def handler(event, context):
    return {"statusCode": 200, "body": json.dumps({"marker": "invoked"})}
'''


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A method whose Lambda URI names a nonexistent alias fails with 500 and never runs the function,
    while a sibling method on the same function's real alias returns the invoked marker."""
    apigw = ctx.client("apigateway")
    lam = ctx.client("lambda")

    role_arn = _create_lambda_role(ctx)
    fn = _create_function(ctx, _CODE, role_arn)
    version = lam.publish_version(FunctionName=fn["name"])["Version"]
    alias_name = "live"
    lam.create_alias(FunctionName=fn["name"], Name=alias_name, FunctionVersion=version)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=fn["name"], Name=alias_name))

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"), tags={"sim2real:managed": "true"}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    account_id = fn["arn"].split(":")[4]

    good_resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="good")["id"]
    apigw.put_method(restApiId=api_id, resourceId=good_resource, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=good_resource,
        httpMethod="GET",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}:{alias_name}/invocations"
        ),
    )
    _add_invoke_permission(
        ctx, fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*/*",
        "sim2real-good-invoke", qualifier=alias_name,
    )

    bad_resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="bad")["id"]
    apigw.put_method(restApiId=api_id, resourceId=bad_resource, httpMethod="GET", authorizationType="NONE")
    missing_alias_arn = f"{fn['arn']}:sim2real-missing-alias"
    apigw.put_integration(
        restApiId=api_id,
        resourceId=bad_resource,
        httpMethod="GET",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{missing_alias_arn}/invocations"
        ),
    )
    # No add_permission for the nonexistent alias: it cannot be granted, and test_invoke_method
    # does not enforce the Lambda resource policy, so the grant does not decide this outcome.

    good_resp = apigw.test_invoke_method(restApiId=api_id, resourceId=good_resource, httpMethod="GET")
    assert good_resp["status"] == 200, f"positive control: real alias must invoke, got {good_resp}"
    good_body = json.loads(good_resp["body"])
    assert good_body["marker"] == "invoked", f"expected marker 'invoked', got {good_body}"

    bad_resp = apigw.test_invoke_method(restApiId=api_id, resourceId=bad_resource, httpMethod="GET")
    assert bad_resp["status"] == 500, f"nonexistent alias must fail backend invocation, got {bad_resp}"
    # API Gateway logs a nonexistent-qualifier invoke failure as a permissions error, not a
    # not-found error; this log line pins the cause, not just "some 5xx".
    assert "Invalid permissions on Lambda function" in bad_resp.get("log", ""), (
        f"expected the alias-not-found configuration-error log line, got log={bad_resp.get('log')!r}"
    )
    assert "invoked" not in bad_resp["body"], (
        f"effect must be absent: the function body must never run, got body={bad_resp['body']!r}"
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
                Tags={"sim2real:managed": "true"},
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
