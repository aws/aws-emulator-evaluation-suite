"""cfn-sam-bare-managed-policy-name-and-numeric-tag-literals-with-deployment-stage."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sam-bare-managed-policy-name-and-numeric-tag-literals-with-deployment-stage"

GROUP = "deploy-sam-transform"

SERVICES = ["apigateway", "cloudformation", "iam", "lambda"]

# A real AWS managed policy unrelated to the one AWS::Serverless::Function always grants by
# default, so its presence on the role can only come from the bare name in Policies.
_BARE_POLICY_NAME = "AmazonS3ReadOnlyAccess"
_BARE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
_DEFAULT_BASIC_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

_CODE = "def handler(event, context):\n    return 'ok'\n"

_PROPAGATION_S = 150.0


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll ``probe()`` until ``predicate`` holds; return the final value (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_stack_and_wait(cfn, stack_name: str, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE; a stack already gone is fine."""
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in msg:
                return "GONE"
            raise

    _poll_until(_status, lambda s: s in {"DELETE_COMPLETE", "GONE"}, timeout_s=timeout_s,
                interval_s=5.0, description=f"delete stack {stack_name}")


def _invoke_policy(ctx) -> str:
    """A resource policy admitting execute-api:Invoke only from the runner's own egress."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "execute-api:Invoke",
            "Resource": "execute-api:/*",
            "Condition": {"IpAddress": {"aws:SourceIp": ctx.ingress_cidrs()}},
        }],
    })


def _template(fn_name: str, api_name: str, stage_name: str, policy: str) -> str:
    """A SAM function whose Policies is one bare managed-policy name and whose Environment and
    Tags carry a number and a boolean, beside a raw Deployment that sets its own StageName."""
    return json.dumps({
        "Transform": "AWS::Serverless-2016-10-31",
        "Resources": {
            "Fn": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "FunctionName": fn_name,
                    "Handler": "index.handler",
                    "Runtime": "python3.12",
                    "InlineCode": _CODE,
                    "Policies": [_BARE_POLICY_NAME],
                    "Environment": {"Variables": {"RetryLimit": 3, "DebugMode": True}},
                    "Tags": {"BuildNumber": 7, "IsProd": False},
                },
            },
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {
                    "Name": api_name,
                    "EndpointConfiguration": {"Types": ["REGIONAL"]},
                    "Policy": policy,
                },
            },
            "Resource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "PathPart": "widgets",
                },
            },
            "Method": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Ref": "Resource"},
                    "HttpMethod": "GET",
                    "AuthorizationType": "NONE",
                    "Integration": {
                        "Type": "MOCK",
                        "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                        "IntegrationResponses": [
                            {"StatusCode": "200", "ResponseTemplates": {
                                "application/json": '{"ok": true}'}},
                        ],
                    },
                    "MethodResponses": [{"StatusCode": "200"}],
                },
            },
            # No separate AWS::ApiGateway::Stage resource: the Deployment's own StageName
            # property is what creates the stage.
            "Deployment": {
                "Type": "AWS::ApiGateway::Deployment",
                "DependsOn": "Method",
                "Properties": {"RestApiId": {"Ref": "RestApi"}, "StageName": stage_name},
            },
        },
    })


def _attached_arns(iam, role_name: str) -> list[str]:
    return sorted(
        p["PolicyArn"]
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name)
        for p in page["AttachedPolicies"]
    )


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _get_http(url: str, verify) -> tuple[int | None, str]:
    try:
        with urllib.request.urlopen(  # noqa: S310 - fixed https scheme
            url, timeout=20, context=_ssl_context(verify)
        ) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")
    except urllib.error.URLError:
        return None, ""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A bare managed-policy name in a SAM function's Policies attaches that policy's ARN beside
    the default basic-execution one, a number and a boolean in String-typed properties read back
    as strings, and deleting the stack removes a Deployment's own self-created stage cleanly."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    awslambda = ctx.client("lambda")
    ag = ctx.client("apigateway")

    fn_name = ctx.unique_name("sim2real-xsvc-fn-")
    api_name = ctx.unique_name("sim2real-xsvc-api-")
    stack_name = ctx.unique_name("sim2real-xsvc-stk-")
    stage_name = "s" + ctx.unique_name("")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(fn_name, api_name, stage_name, _invoke_policy(ctx)),
        Capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))

    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s.endswith(("_COMPLETE", "_FAILED")),
        timeout_s=300.0, interval_s=5.0, description=f"stack {stack_name}",
    )
    assert status == "CREATE_COMPLETE", f"stack {stack_name!r} ended {status!r}, not CREATE_COMPLETE"

    resources = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    }
    role_name = resources["FnRole"]
    api_id = resources["RestApi"]

    # ---- (a) the bare managed-policy name expands onto the role, beside the default ----------
    attached = _attached_arns(iam, role_name)
    assert attached == sorted([_DEFAULT_BASIC_ARN, _BARE_POLICY_ARN]), (
        f"a bare managed-policy name in Policies must resolve to {_BARE_POLICY_ARN!r} and sit "
        f"beside the default basic-execution policy; role {role_name!r} carries {attached!r}"
    )

    # ---- (b) a number and a boolean in a String-typed property are stored as strings --------
    cfg = awslambda.get_function_configuration(FunctionName=fn_name)
    env_vars = cfg.get("Environment", {}).get("Variables", {})
    assert env_vars == {"RetryLimit": "3", "DebugMode": "true"}, (
        f"the integer 3 and the boolean true given for Environment.Variables must read back as "
        f"the strings '3' and 'true'; got {env_vars!r}"
    )
    fn_arn = cfg["FunctionArn"]
    fn_tags = awslambda.list_tags(Resource=fn_arn)["Tags"]
    assert fn_tags.get("BuildNumber") == "7", (
        f"the integer 7 given for the function's Tags.BuildNumber must read back as '7'; got "
        f"{fn_tags.get('BuildNumber')!r}"
    )
    assert fn_tags.get("IsProd") == "false", (
        f"the boolean false given for the function's Tags.IsProd must read back as 'false'; got "
        f"{fn_tags.get('IsProd')!r}"
    )

    # ---- (c) the Deployment's own StageName created a real, serving stage -------------------
    stage = ag.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage["deploymentId"] == resources["Deployment"], (
        f"stage {stage_name!r} must point at the Deployment resource "
        f"{resources['Deployment']!r}; GetStage reported deploymentId {stage['deploymentId']!r}"
    )

    url = f"{ctx.rest_api_url(api_id, stage_name)}/widgets"
    status_code, body = _poll_until(
        lambda: _get_http(url, ctx.http_verify),
        lambda r: r[0] == 200,
        timeout_s=_PROPAGATION_S, interval_s=5.0,
        description="the deployed stage serving its MOCK integration",
    )
    assert status_code == 200, f"GET {url} returned status {status_code!r}, body {body[:200]!r}"
    assert json.loads(body) == {"ok": True}, f"GET {url} returned body {body!r}"

    # ---- delete the stack and prove every resource type is actually gone --------------------
    _delete_stack_and_wait(cfn, stack_name)

    code, message = _error(lambda: cfn.describe_stacks(StackName=stack_name))
    assert (code, message) == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
        f"a deleted stack must be unknown to DescribeStacks; got {code}: {message!r}"
    )

    code, message = _error(lambda: ag.get_rest_api(restApiId=api_id))
    assert code == "NotFoundException", f"expected the REST API gone, got {code}: {message!r}"
    assert message == f"Invalid API identifier specified {ctx.account}:{api_id}", (
        f"unexpected not-found message for the deleted REST API: {message!r}"
    )

    code, message = _error(lambda: awslambda.get_function(FunctionName=fn_name))
    assert code == "ResourceNotFoundException", f"expected the function gone, got {code}: {message!r}"
    assert message == f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_name}", (
        f"unexpected not-found message for the deleted function: {message!r}"
    )

    code, message = _error(lambda: iam.get_role(RoleName=role_name))
    role_gone = ("NoSuchEntity", f"The role with name {role_name} cannot be found.")
    assert (code, message) == role_gone, (
        f"expected the synthesized role gone, got {code}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
