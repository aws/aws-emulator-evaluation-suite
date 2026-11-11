"""deploy-cfn-apigateway-access-logging-enabled-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-apigateway-access-logging-enabled-positive"
GROUP = "log-delivery"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_PUSH_LOGS_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AccessLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      RetentionInDays: 1

  RestApi:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: !Sub "${AWS::StackName}-api"

  PingResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref RestApi
      ParentId: !GetAtt RestApi.RootResourceId
      PathPart: ping

  PingMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: !Ref PingResource
      HttpMethod: GET
      AuthorizationType: NONE
      Integration:
        Type: MOCK
        RequestTemplates:
          application/json: '{"statusCode": 200}'
        IntegrationResponses:
          - StatusCode: '200'
            ResponseTemplates:
              application/json: '{"message": "pong"}'
      MethodResponses:
        - StatusCode: '200'

  ApiDeployment:
    Type: AWS::ApiGateway::Deployment
    DependsOn: PingMethod
    Properties:
      RestApiId: !Ref RestApi

  ApiStage:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref RestApi
      DeploymentId: !Ref ApiDeployment
      StageName: prod
      AccessLogSetting:
        DestinationArn: !GetAtt AccessLogGroup.Arn
        Format: '$context.requestId $context.httpMethod $context.status $context.resourcePath'

Outputs:
  ApiId:
    Value: !Ref RestApi
  AccessLogGroupName:
    Value: !Ref AccessLogGroup
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:metrics", "dp:api", "dp:endpoint", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """A stage with AccessLogSetting enabled actually delivers request-level access log
    entries to the configured CloudWatch log group after real traffic hits the API."""
    apigw = ctx.client("apigateway")
    iam = ctx.client("iam")
    original_role_arn = apigw.get_account().get("cloudwatchRoleArn")

    if not original_role_arn:
        role_name = ctx.unique_name("sim2real-xsvc-apigw-cwlogs-")
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "apigateway.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Tags=_xsvc_tags_kv(),
        )["Role"]["Arn"]
        iam.attach_role_policy(RoleName=role_name, PolicyArn=_PUSH_LOGS_POLICY_ARN)

        def _delete_role():
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=_PUSH_LOGS_POLICY_ARN)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
            try:
                iam.delete_role(RoleName=role_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise

        def _restore_account():
            apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": original_role_arn or ""}])

        # LIFO: the account setting is put back before the role it points at is deleted.
        ctx.on_cleanup(_delete_role)
        ctx.on_cleanup(_restore_account)

        # IAM role/policy propagation: API Gateway validates the role ARN synchronously and
        # rejects it with BadRequestException until the just-created role/policy is visible.
        def _set_cloudwatch_role():
            apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}])

        _retry_on_client_error(
            _set_cloudwatch_role,
            error_codes={"BadRequestException"},
            timeout_s=90.0,
            interval_s=5.0,
            description="apigateway account accepting the new cloudwatchRoleArn (IAM propagation)",
        )
        _poll_until(
            lambda: apigw.get_account().get("cloudwatchRoleArn"),
            lambda v: v == role_arn,
            timeout_s=30.0,
            interval_s=3.0,
            description="API Gateway account cloudwatchRoleArn propagation",
        )
        # IAM role/policy propagation before API Gateway can actually assume the role to
        # write logs (distinct from the config-plane propagation just polled above) is
        # covered by the bounded polls below: the CFN stack create plus the up-to-45s
        # endpoint poll plus the up-to-150s access-log poll already span the window a
        # naked sleep here used to approximate.

    result = _deploy_cfn(ctx, _TEMPLATE)
    api_url = f"{ctx.api_url(result['outputs']['ApiId'], 'prod')}/ping"
    log_group_name = result["outputs"]["AccessLogGroupName"]

    logs = ctx.client("logs")

    def _find_access_log():
        try:
            resp = logs.filter_log_events(logGroupName=log_group_name, filterPattern="GET")
        except ClientError:
            return []
        return resp.get("events", [])

    # MEASURED on real AWS: immediately after a stage's AccessLogSetting (and the account
    # cloudwatchRoleArn it depends on) is applied, the delivery pipeline has a warm-up
    # window during which requests are served (200) but their access-log record is dropped
    # entirely, not merely delayed -- polling the log group after the window has already
    # missed its one request never succeeds no matter how long the deadline is. So the
    # request is RE-ISSUED on every polling interval instead of fired once up front; each
    # reissue is asserted to return 200 (positive control), and the loop stops the moment
    # any of them lands in the log group.
    status, body, events = _request_until_logged(
        api_url,
        _find_access_log,
        timeout_s=150.0,
        interval_s=10.0,
        description="access log entries delivered to the configured log group",
    )
    parsed_body = json.loads(body)
    assert parsed_body["message"] == "pong", f"expected the MOCK integration body 'pong', got {parsed_body!r}"
    assert any("/ping" in e["message"] for e in events), "no access log entry referenced the /ping resource path"


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


def _retry_on_client_error(action, *, error_codes, timeout_s=60.0, interval_s=5.0, description="action"):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return action()
        except ClientError as e:
            last_exc = e
            if e.response.get("Error", {}).get("Code") not in error_codes:
                raise
            time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s") from last_exc



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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return 'GONE'

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
    template_body = template.read_text() if isinstance(template, Path) else template
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


def _http_request(method, url, body=None, timeout=15):
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _request_until_logged(url, probe, *, timeout_s=150.0, interval_s=10.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    attempts = 0
    status, body = None, None
    while True:
        status, body = _http_request("GET", url)
        attempts += 1
        assert status == 200, f"expected 200 from GET {url} on attempt {attempts}, got {status}: {body[:300]!r}"
        events = probe()
        if events:
            return status, body, events
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not met within {timeout_s}s after {attempts} identical requests"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
