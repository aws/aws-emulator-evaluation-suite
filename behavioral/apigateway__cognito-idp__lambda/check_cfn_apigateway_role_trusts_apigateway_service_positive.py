"""cfn-apigateway-role-trusts-apigateway-service-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-apigateway-role-trusts-apigateway-service-positive"
GROUP = "iam-trust"
SERVICES = ["apigateway", "cognito-idp", "lambda"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:metrics", "concern:representation", "dp:endpoint", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """A CFN-created account role whose AssumeRolePolicyDocument trusts apigateway.amazonaws.com
    lets API Gateway actually assume it and push execution logs to CloudWatch."""
    log_group_name: str | None = None
    # AWS::ApiGateway::Account sets the account-global cloudwatchRoleArn (one per account per
    # region, shared by every REST API); CFN never reverts it on stack delete.
    apigw = ctx.client("apigateway")
    prior_cw_role_arn = apigw.get_account().get("cloudwatchRoleArn")

    def _restore_account_cw_role() -> None:
        apigw.update_account(
            patchOperations=[
                {"op": "replace", "path": "/cloudwatchRoleArn", "value": prior_cw_role_arn or ""}
            ]
        )

    ctx.on_cleanup(_restore_account_cw_role)
    try:
        api_name = ctx.unique_name("sim2real-apigw-trust-")
        result = _deploy_cfn(ctx, _template(api_name))
        role_name = result["outputs"]["RoleName"]
        api_id = result["outputs"]["ApiId"]
        log_group_name = f"API-Gateway-Execution-Logs_{api_id}/test"
        ctx.on_cleanup(lambda: _delete_log_group_quiet(ctx, log_group_name))

        iam = ctx.client("iam")
        trust_doc = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
        statements = trust_doc["Statement"]
        assert len(statements) == 1, f"expected exactly one trust statement, got {statements}"
        stmt = statements[0]
        assert stmt["Effect"] == "Allow", f"expected Allow, got {stmt['Effect']}"
        principal = stmt["Principal"]["Service"]
        if isinstance(principal, list):
            assert principal == ["apigateway.amazonaws.com"], f"unexpected principal list: {principal}"
        else:
            assert principal == "apigateway.amazonaws.com", f"unexpected principal: {principal}"

        url = f"{ctx.rest_api_url(api_id, 'test')}/ping"
        status, body = _poll_invoke_until(url, {200}, timeout_s=90, interval_s=3)
        assert status == 200, f"expected 200 from the mock integration, got {status}: {body}"

        # The account-level CloudWatchRoleArn can take a few minutes to propagate before API
        # Gateway actually assumes it for log delivery, and early invokes may be dropped while
        # that propagates — so keep re-invoking on every poll cycle rather than relying on the
        # single request above to have been logged.
        def _invoke_and_check_logs() -> bool:
            _invoke(url)
            return _has_execution_logs(ctx, log_group_name)

        found = _poll_until(
            _invoke_and_check_logs,
            lambda v: v,
            timeout_s=240.0,
            interval_s=10.0,
            description=f"execution logs delivered to {log_group_name}",
        )
        assert found is True, "execution logs never appeared in the destination log group"
    finally:
        pass


# ===== check-specific plumbing =====


def _has_execution_logs(ctx, log_group: str) -> bool:
    logs = ctx.client("logs")
    try:
        streams = logs.describe_log_streams(
            logGroupName=log_group, orderBy="LastEventTime", descending=True, limit=5
        )["logStreams"]
    except logs.exceptions.ResourceNotFoundException:
        return False
    for stream in streams:
        events = logs.get_log_events(
            logGroupName=log_group, logStreamName=stream["logStreamName"], limit=10
        )["events"]
        if events:
            return True
    return False


def _delete_log_group_quiet(ctx, log_group: str) -> None:
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _invoke(url: str, timeout: float = 10.0) -> tuple[int, str]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _poll_invoke_until(url: str, target_statuses: set[int], timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        status, body = _invoke(url)
        last = (status, body)
        if status in target_statuses:
            return status, body
        time.sleep(interval_s)
    raise AssertionError(f"never observed status in {target_statuses}; last={last}")


def _template(api_name: str) -> str:
    template = {
        "Resources": {
            "CwRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "apigateway.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
                    ],
                },
            },
            "Account": {
                "Type": "AWS::ApiGateway::Account",
                "Properties": {"CloudWatchRoleArn": {"Fn::GetAtt": ["CwRole", "Arn"]}},
            },
            "Api": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": api_name, "EndpointConfiguration": {"Types": ["REGIONAL"]}},
            },
            "Res": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "Api"},
                    "ParentId": {"Fn::GetAtt": ["Api", "RootResourceId"]},
                    "PathPart": "ping",
                },
            },
            "Method": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "Api"},
                    "ResourceId": {"Ref": "Res"},
                    "HttpMethod": "GET",
                    "AuthorizationType": "NONE",
                    "Integration": {
                        "Type": "MOCK",
                        "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                        "IntegrationResponses": [
                            {"StatusCode": "200", "ResponseTemplates": {"application/json": '{"ok": true}'}}
                        ],
                    },
                    "MethodResponses": [{"StatusCode": "200"}],
                },
            },
            "Deployment": {
                "Type": "AWS::ApiGateway::Deployment",
                "DependsOn": "Method",
                "Properties": {"RestApiId": {"Ref": "Api"}},
            },
            "Stage": {
                "Type": "AWS::ApiGateway::Stage",
                "DependsOn": "Account",
                "Properties": {
                    "RestApiId": {"Ref": "Api"},
                    "DeploymentId": {"Ref": "Deployment"},
                    "StageName": "test",
                    "MethodSettings": [
                        {"ResourcePath": "/*", "HttpMethod": "*", "LoggingLevel": "INFO", "DataTraceEnabled": True}
                    ],
                },
            },
        },
        "Outputs": {
            "RoleName": {"Value": {"Ref": "CwRole"}},
            "ApiId": {"Value": {"Ref": "Api"}},
        },
    }
    return json.dumps(template)


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
