"""deploy-rest-api-stage-cfn-invoke-behaves."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-rest-api-stage-cfn-invoke-behaves"
GROUP = "state-machine"
SERVICES = ["apigateway"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  MarkerParam:
    Type: String
Resources:
  Api:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: !Sub '${AWS::StackName}-api'
  EchoResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref Api
      ParentId: !GetAtt Api.RootResourceId
      PathPart: echo
  EchoMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref Api
      ResourceId: !Ref EchoResource
      HttpMethod: GET
      AuthorizationType: NONE
      Integration:
        Type: MOCK
        RequestTemplates:
          application/json: '{"statusCode": 200}'
        IntegrationResponses:
          - StatusCode: '200'
            ResponseTemplates:
              application/json: !Sub '{"message": "pong-${MarkerParam}"}'
      MethodResponses:
        - StatusCode: '200'
  ApiDeployment:
    Type: AWS::ApiGateway::Deployment
    DependsOn: EchoMethod
    Properties:
      RestApiId: !Ref Api
  ApiStage:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref Api
      DeploymentId: !Ref ApiDeployment
      StageName: sim2real
Outputs:
  RestApiId:
    Value: !Ref Api
  ResourceId:
    Value: !Ref EchoResource
  StageName:
    Value: !Ref ApiStage
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A RestApi/Deployment/Stage stack deployed via CloudFormation answers TestInvokeMethod with the MOCK
    integration's response template, and after stack deletion GetRestApi fails with 404."""
    marker = ctx.unique_name("agw-echo-")
    stack_name, outputs = _deploy_stack(ctx, _TEMPLATE, parameters={"MarkerParam": marker})

    apigw = ctx.client("apigateway")
    resp = apigw.test_invoke_method(
        restApiId=outputs["RestApiId"],
        resourceId=outputs["ResourceId"],
        httpMethod="GET",
    )
    assert resp["status"] == 200, f"expected 200, got {resp['status']}: {resp.get('body')}"
    body = json.loads(resp["body"])
    assert body == {"message": f"pong-{marker}"}, f"unexpected integration response body: {body}"

    # Teardown: delete the stack and confirm the RestApi is genuinely gone, not just
    # CFN-reported as deleted.
    _delete_stack(ctx, stack_name)
    err = _error(lambda: apigw.get_rest_api(restApiId=outputs["RestApiId"]))
    expected = ("NotFoundException", f"Invalid API identifier specified {ctx.account}:{outputs['RestApiId']}")
    assert err == expected, f"expected {expected!r} after stack teardown, got {err!r}"


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises, so an
    accepted call is reported as accepted rather than as a wrong error code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _deploy_stack(ctx, template_body: str, parameters: dict | None = None):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-agw-")
    kwargs = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Capabilities": ["CAPABILITY_IAM"],
        "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_for_stack(ctx, stack_name, {"CREATE_COMPLETE"}, {"CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"})
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}
    return stack_name, outputs


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_for_stack(ctx, stack_name, {"DELETE_COMPLETE"}, set(), missing_ok=True)


def _wait_for_stack(
    ctx,
    stack_name: str,
    ok_statuses: set,
    bad_statuses: set,
    missing_ok: bool = False,
    timeout_s: float = 420.0,
    interval_s: float = 6.0,
) -> None:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if missing_ok and "does not exist" in str(exc):
                return
            raise
        if not stacks:
            if missing_ok:
                return
            raise AssertionError(f"stack {stack_name} vanished unexpectedly")
        last_status = stacks[0]["StackStatus"]
        if last_status in ok_statuses:
            return
        if last_status in bad_statuses:
            raise AssertionError(f"stack {stack_name} entered {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not settle within {timeout_s}s (last={last_status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
