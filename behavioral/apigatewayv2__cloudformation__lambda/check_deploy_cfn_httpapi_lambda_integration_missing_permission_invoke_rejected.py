"""deploy-cfn-httpapi-lambda-integration-missing-permission-invoke-rejected."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-httpapi-lambda-integration-missing-permission-invoke-rejected"
GROUP = "deploy"
SERVICES = ["apigatewayv2", "cloudformation", "lambda"]

_CREATE_TIMEOUT_S = 240.0
_DELETE_TIMEOUT_S = 180.0
_SERVE_DEADLINE_S = 90.0
_POLL_S = 3.0


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An IAM-authorized HttpApi route with no `AWS::Lambda::Permission` deploys and reads back wired,
    but a signed GET answers 500; a sibling route carrying the permission serves the function.
    """
    cfn = ctx.client("cloudformation")
    agw = ctx.client("apigatewayv2")
    lam = ctx.client("lambda")

    stack = ctx.unique_name("sim2real-httpperm-")
    fn_name = ctx.unique_name("sim2real-httpperm-fn-")
    role_name = ctx.unique_name("sim2real-httpperm-role-")
    allowed_marker = ctx.unique_name("allowed-")
    log_group = f"/aws/lambda/{fn_name}"

    template = _template(stack, fn_name, role_name)
    cfn.create_stack(
        StackName=stack, TemplateBody=json.dumps(template), Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda: _reap_log_group(logs, log_group))
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack, timeout_s=_DELETE_TIMEOUT_S))

    _wait_stack(ctx, stack, "CREATE_COMPLETE", timeout_s=_CREATE_TIMEOUT_S)

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}
    for key in ("ApiId", "ApiEndpoint"):
        assert key in outputs, f"stack outputs {sorted(outputs)!r} lack {key!r}"
    api_id = outputs["ApiId"]
    endpoint = outputs["ApiEndpoint"].rstrip("/")

    # ---- control plane: both routes and both integrations are wired, deploy claims success ---
    routes = {r["RouteKey"]: r for r in agw.get_routes(ApiId=api_id)["Items"]}
    assert set(routes) == {"ANY /allowed", "ANY /denied"}, (
        f"GetRoutes on {api_id!r} returned {sorted(routes)!r}, expected both routes"
    )
    integrations = {i["IntegrationId"]: i for i in agw.get_integrations(ApiId=api_id)["Items"]}
    assert len(integrations) == 2, (
        f"GetIntegrations on {api_id!r} returned {integrations!r}, expected two integrations"
    )
    auth = {key: r.get("AuthorizationType") for key, r in routes.items()}
    assert auth == {"ANY /allowed": "AWS_IAM", "ANY /denied": "AWS_IAM"}, (
        f"GetRoutes reports AuthorizationType {auth!r}, expected AWS_IAM on both routes"
    )
    for route in routes.values():
        target = route.get("Target", "")
        assert target.startswith("integrations/") and target.removeprefix("integrations/") in (
            integrations
        ), f"route {route!r} targets an integration GetIntegrations does not list"
    assert all(i.get("IntegrationType") == "AWS_PROXY" for i in integrations.values()), (
        f"not every integration is AWS_PROXY: {integrations!r}"
    )

    # ---- data plane: the allowed route serves; the denied route answers 500 ------------------
    allowed_status, allowed_body = _http_until(
        ctx, f"{endpoint}/allowed", params={"marker": allowed_marker}, want=200,
        deadline_s=_SERVE_DEADLINE_S,
    )
    assert allowed_status == 200 and json.loads(allowed_body) == {"marker": allowed_marker}, (
        f"GET /allowed returned {allowed_status} {allowed_body!r}, expected 200 "
        f"{{'marker': {allowed_marker!r}}}"
    )
    denied_status, denied_body = _http(ctx, f"{endpoint}/denied", params={})
    assert denied_status == 500, (
        f"GET /denied through a route with no Lambda::Permission returned status "
        f"{denied_status!r}, expected 500: {denied_body!r}"
    )
    assert json.loads(denied_body) == {"message": "Internal Server Error"}, (
        f"GET /denied returned body {denied_body!r}, expected the generic Internal Server "
        f"Error body API Gateway returns when it cannot invoke the backend"
    )

    # ---- delete in-band: the API, the function and the role are all gone --------------------
    _delete_stack_and_wait(ctx, stack, timeout_s=_DELETE_TIMEOUT_S)

    gone_stack = _client_error(lambda: cfn.describe_stacks(StackName=stack))
    assert gone_stack.response["Error"]["Code"] == "ValidationError", gone_stack.response["Error"]
    assert gone_stack.response["Error"]["Message"] == f"Stack with id {stack} does not exist", (
        gone_stack.response["Error"]["Message"]
    )
    gone_api = _client_error(lambda: agw.get_api(ApiId=api_id))
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
    """An HTTP API with two ANY routes to the same Lambda: one route's integration is granted
    invoke, the other's is not."""
    code = (
        "import json\n"
        "def handler(event, context):\n"
        "    params = event.get('queryStringParameters') or {}\n"
        "    return {'statusCode': 200, 'headers': {'content-type': 'application/json'},\n"
        "            'body': json.dumps({'marker': params.get('marker')})}\n"
    )
    fn_arn = {"Fn::GetAtt": ["Fn", "Arn"]}

    def integration() -> dict:
        return {
            "Type": "AWS::ApiGatewayV2::Integration",
            "Properties": {
                "ApiId": {"Ref": "Api"},
                "IntegrationType": "AWS_PROXY",
                "IntegrationUri": fn_arn,
                "PayloadFormatVersion": "2.0",
            },
        }

    def route(key: str, integration_id: str) -> dict:
        return {
            "Type": "AWS::ApiGatewayV2::Route",
            "Properties": {
                "ApiId": {"Ref": "Api"},
                "RouteKey": key,
                # SigV4-only, so the auto-deployed stage is never anonymously invokable.
                "AuthorizationType": "AWS_IAM",
                "Target": {"Fn::Join": ["", ["integrations/", {"Ref": integration_id}]]},
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
                "Type": "AWS::ApiGatewayV2::Api",
                "Properties": {"Name": stack, "ProtocolType": "HTTP"},
            },
            "AllowedIntegration": integration(),
            "DeniedIntegration": integration(),
            "AllowedRoute": route("ANY /allowed", "AllowedIntegration"),
            "DeniedRoute": route("ANY /denied", "DeniedIntegration"),
            "Stage": {
                "Type": "AWS::ApiGatewayV2::Stage",
                "Properties": {"ApiId": {"Ref": "Api"}, "StageName": "$default",
                               "AutoDeploy": True},
            },
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
            "ApiId": {"Value": {"Ref": "Api"}},
            "ApiEndpoint": {"Value": {"Fn::GetAtt": ["Api", "ApiEndpoint"]}},
            "FunctionName": {"Value": {"Ref": "Fn"}},
        },
    }


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


def _ssl_context(verify):
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(ctx, url: str, *, params: dict, timeout_s: float = 20.0) -> tuple[int, bytes]:
    if params:
        url = url + "?" + "&".join(f"{k}={v}" for k, v in params.items())
    target, headers = ctx.endpoint_route(url)
    headers = _sigv4_headers(ctx, target, headers)
    request = urllib.request.Request(target, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout_s,
                                    context=_ssl_context(ctx.http_verify)) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _http_until(ctx, url: str, *, params: dict, want: int, deadline_s: float) -> tuple[int, bytes]:
    deadline = time.monotonic() + deadline_s
    status, body = -1, b""
    while time.monotonic() < deadline:
        status, body = _http(ctx, url, params=params)
        if status == want:
            return status, body
        time.sleep(2.0)
    raise AssertionError(
        f"GET {url} never returned {want} within {deadline_s}s; last status {status} body "
        f"{body[:300]!r}"
    )


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


def _sigv4_headers(ctx, url: str, headers: dict) -> dict:
    """``headers`` plus SigV4 execute-api headers for a GET of ``url``, with this run's credentials."""
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    frozen = ctx.client("apigatewayv2")._request_signer._credentials.get_frozen_credentials()
    request = AWSRequest(method="GET", url=url, headers=dict(headers))
    SigV4Auth(frozen, "execute-api", ctx.region).add_auth(request)
    return dict(request.headers.items())


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
