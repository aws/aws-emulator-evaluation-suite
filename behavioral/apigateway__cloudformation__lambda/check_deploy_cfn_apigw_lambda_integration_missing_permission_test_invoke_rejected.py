"""deploy-cfn-apigw-lambda-integration-missing-permission-test-invoke-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-apigw-lambda-integration-missing-permission-test-invoke-rejected"
GROUP = "deploy"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_CREATE_TIMEOUT_S = 240.0
_DELETE_TIMEOUT_S = 180.0
_POLL_S = 3.0


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS_PROXY method whose Lambda lacks an `AWS::Lambda::Permission`
    deploys clean, but `TestInvokeMethod` fails with the exact missing-permission error; the
    identical integration with the grant present runs the function.
    """
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    stack = ctx.unique_name("sim2real-apigwperm-")
    fn_name = ctx.unique_name("sim2real-apigwperm-fn-")
    role_name = ctx.unique_name("sim2real-apigwperm-role-")
    log_group = f"/aws/lambda/{fn_name}"
    denied_marker = ctx.unique_name("denied-")
    allowed_marker = ctx.unique_name("allowed-")

    template = _template(stack, fn_name, role_name)
    cfn.create_stack(
        StackName=stack, TemplateBody=json.dumps(template), Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )
    ctx.on_cleanup(lambda: _reap_log_group(logs, log_group))
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack, timeout_s=_DELETE_TIMEOUT_S))

    _wait_stack(ctx, stack, "CREATE_COMPLETE", timeout_s=_CREATE_TIMEOUT_S)

    resources = apigw.get_resources(restApiId=_output(ctx, stack, "RestApiId"))["items"]
    by_path = {r.get("path"): r["id"] for r in resources}
    api_id = _output(ctx, stack, "RestApiId")
    assert {"/allowed", "/denied"} <= set(by_path), (
        f"REST API {api_id!r} lacks /allowed or /denied: {resources!r}"
    )

    # ---- positive control FIRST, so its latency bounds the absence window below --------------
    start = time.monotonic()
    allowed = apigw.test_invoke_method(
        restApiId=api_id, resourceId=by_path["/allowed"], httpMethod="ANY",
        body=json.dumps({"marker": allowed_marker}),
    )
    assert allowed["status"] == 200, (
        f"POST /allowed through a method whose Lambda::Permission grants the invoke returned "
        f"status {allowed['status']!r}, expected 200: {allowed.get('log', '')[-600:]!r}"
    )
    _wait_log_line(ctx, logs, log_group, allowed_marker, timeout_s=180.0)
    latency_s = time.monotonic() - start

    # ---- the identical integration, minus the permission, is refused at invoke time ----------
    denied = apigw.test_invoke_method(
        restApiId=api_id, resourceId=by_path["/denied"], httpMethod="ANY",
        body=json.dumps({"marker": denied_marker}),
    )
    assert denied["status"] == 500, (
        f"POST /denied through a method with no Lambda::Permission returned status "
        f"{denied['status']!r}, expected 500: {denied.get('log', '')[-600:]!r}"
    )
    assert json.loads(denied["body"]) == {"message": "Internal server error"}, (
        f"the refused POST /denied body is {denied.get('body')!r}"
    )
    # Each log line is "<timestamp> : <text>"; the timestamp varies, the text is API Gateway's.
    log_texts = [line.split(" : ", 1)[1] for line in denied.get("log", "").splitlines() if " : " in line]
    refusal = "Execution failed due to configuration error: Invalid permissions on Lambda function"
    assert refusal in log_texts, (
        f"the refused POST /denied log has no line {refusal!r}: {denied.get('log', '')[-600:]!r}"
    )

    # ---- effect absent: the function never ran for the denied call ---------------------------
    window_s = max(10.0, 3.0 * latency_s)
    deadline = time.monotonic() + window_s
    seen: list[str] = []
    while True:
        seen.extend(_log_lines(logs, log_group, denied_marker))
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    assert seen == [], (
        f"log group {log_group!r} holds {len(seen)} line(s) carrying the denied marker "
        f"{denied_marker!r} over a {window_s:.1f}s window: the function ran although its "
        f"execution role was never granted apigateway:invoke for this method"
    )

    # ---- delete in-band: the API, the function and the role are all gone --------------------
    _delete_stack_and_wait(ctx, stack, timeout_s=_DELETE_TIMEOUT_S)

    gone_stack = _client_error(lambda: cfn.describe_stacks(StackName=stack))
    assert gone_stack.response["Error"]["Code"] == "ValidationError", gone_stack.response["Error"]
    assert gone_stack.response["Error"]["Message"] == f"Stack with id {stack} does not exist", (
        gone_stack.response["Error"]["Message"]
    )
    gone_api = _client_error(lambda: apigw.get_rest_api(restApiId=api_id))
    assert gone_api.response["Error"]["Code"] == "NotFoundException", gone_api.response["Error"]
    assert gone_api.response["Error"]["Message"] == (
        f"Invalid API identifier specified {ctx.account}:{api_id}"
    ), gone_api.response["Error"]["Message"]
    gone_fn = _client_error(lambda: lam.get_function(FunctionName=fn_name))
    assert gone_fn.response["Error"]["Code"] == "ResourceNotFoundException", gone_fn.response["Error"]
    assert gone_fn.response["Error"]["Message"] == (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_name}"
    ), gone_fn.response["Error"]["Message"]
    gone_role = _client_error(lambda: ctx.client("iam").get_role(RoleName=role_name))
    assert gone_role.response["Error"]["Code"] == "NoSuchEntity", gone_role.response["Error"]
    assert gone_role.response["Error"]["Message"] == (
        f"The role with name {role_name} cannot be found."
    ), gone_role.response["Error"]["Message"]


# ===== self-contained helpers =====


def _template(stack: str, fn_name: str, role_name: str) -> dict:
    """A RestApi with two paths proxying to the same Lambda: one grants invoke, one does not."""
    code = (
        "import json\n"
        "def handler(event, context):\n"
        "    body = json.loads(event.get('body') or '{}')\n"
        "    marker = body.get('marker')\n"
        "    print('handled marker ' + str(marker))\n"
        "    return {'statusCode': 200, 'body': json.dumps({'marker': marker})}\n"
    )
    integration_uri = {
        "Fn::Join": ["", [
            "arn:", {"Ref": "AWS::Partition"}, ":apigateway:", {"Ref": "AWS::Region"},
            ":lambda:path/2015-03-31/functions/", {"Fn::GetAtt": ["Fn", "Arn"]}, "/invocations",
        ]]
    }

    def method(resource_ref: str) -> dict:
        return {
            "Type": "AWS::ApiGateway::Method",
            "Properties": {
                "RestApiId": {"Ref": "Api"},
                "ResourceId": {"Ref": resource_ref},
                "HttpMethod": "ANY",
                "AuthorizationType": "NONE",
                "Integration": {
                    "Type": "AWS_PROXY",
                    "IntegrationHttpMethod": "POST",
                    "Uri": integration_uri,
                },
            },
        }

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": fn_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                    "Code": {"ZipFile": code},
                },
            },
            "Api": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": stack},
            },
            "AllowedResource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "Api"},
                    "ParentId": {"Fn::GetAtt": ["Api", "RootResourceId"]},
                    "PathPart": "allowed",
                },
            },
            "DeniedResource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "Api"},
                    "ParentId": {"Fn::GetAtt": ["Api", "RootResourceId"]},
                    "PathPart": "denied",
                },
            },
            "AllowedMethod": method("AllowedResource"),
            "DeniedMethod": method("DeniedResource"),
            "AllowedPermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "Fn"},
                    "Principal": "apigateway.amazonaws.com",
                    "SourceArn": {
                        "Fn::Join": ["", [
                            "arn:", {"Ref": "AWS::Partition"}, ":execute-api:",
                            {"Ref": "AWS::Region"}, ":", {"Ref": "AWS::AccountId"}, ":",
                            {"Ref": "Api"}, "/*/*/allowed",
                        ]]
                    },
                },
            },
        },
        "Outputs": {
            "RestApiId": {"Value": {"Ref": "Api"}},
            "FunctionName": {"Value": {"Ref": "Fn"}},
        },
    }


def _output(ctx, stack: str, key: str) -> str:
    cfn = ctx.client("cloudformation")
    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}
    assert key in outputs, f"stack {stack!r} outputs {sorted(outputs)!r} lack {key!r}"
    return outputs[key]


def _wait_stack(ctx, stack: str, want: str, *, timeout_s: float) -> None:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    status = "never read"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if status == want:
            return
        if status.endswith("_FAILED") or "ROLLBACK" in status:
            reasons = [
                f"{e.get('LogicalResourceId')}: {e.get('ResourceStatusReason')}"
                for e in cfn.describe_stack_events(StackName=stack)["StackEvents"]
                if e.get("ResourceStatus", "").endswith("FAILED")
            ][:5]
            raise AssertionError(f"stack {stack!r} reached {status!r}; failures {reasons!r}")
        time.sleep(_POLL_S)
    raise AssertionError(f"stack {stack!r} not {want} within {timeout_s}s (last {status!r})")


def _wait_log_line(ctx, logs, log_group: str, needle: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    lines: list[str] = []
    while time.monotonic() < deadline:
        lines = _log_lines(logs, log_group, needle)
        if lines:
            return
        time.sleep(_POLL_S)
    raise AssertionError(f"no line in {log_group!r} contains {needle!r} within {timeout_s}s")


def _log_lines(logs, log_group: str, needle: str) -> list[str]:
    try:
        return [
            e["message"]
            for page in logs.get_paginator("filter_log_events").paginate(
                logGroupName=log_group, filterPattern=f'"{needle}"')
            for e in page["events"]
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise


def _client_error(fn) -> ClientError:
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("call succeeded but was expected to be refused")


def _stack_missing(exc: ClientError) -> bool:
    error = exc.response["Error"]
    return error["Code"] == "ValidationError" and "does not exist" in str(error.get("Message", ""))


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if _stack_missing(exc):
            return
        raise
    deadline = time.monotonic() + timeout_s
    status = "never read"
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _stack_missing(exc):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(_POLL_S)
    raise AssertionError(f"stack {stack!r} not deleted within {timeout_s}s (last {status!r})")


def _reap_log_group(logs, name: str, *, reads: int = 3, budget_s: float = 180.0) -> None:
    """Delete log group `name` until `reads` consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log group {name!r} still present after {budget_s}s")
            time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
