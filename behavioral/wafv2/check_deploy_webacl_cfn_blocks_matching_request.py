"""deploy-webacl-cfn-blocks-matching-request."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-webacl-cfn-blocks-matching-request"
GROUP = "deploy"
SERVICES = ["wafv2"]

_BLOCK_HEADER = "x-simparity-block"
_BLOCK_VALUE = "block-me"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed WebACL whose header-match rule is Block resolves for its API Gateway stage and answers
    matching requests 403 with body {"message":"Forbidden"}, non-matching ones 200."""
    apigw = ctx.client("apigateway")
    wafv2 = ctx.client("wafv2")
    cfn = ctx.client("cloudformation")

    stage = _create_apigw_stage(ctx, apigw)

    webacl_name = ctx.unique_name("sim2real-waf-block-")
    template = f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  BlockWebACL:
    Type: AWS::WAFv2::WebACL
    Properties:
      Name: {webacl_name}
      Scope: REGIONAL
      DefaultAction:
        Allow: {{}}
      VisibilityConfig:
        SampledRequestsEnabled: true
        CloudWatchMetricsEnabled: true
        MetricName: {webacl_name}
      Rules:
        - Name: BlockHeaderRule
          Priority: 0
          Action:
            Block: {{}}
          Statement:
            ByteMatchStatement:
              SearchString: "{_BLOCK_VALUE}"
              FieldToMatch:
                SingleHeader:
                  Name: "{_BLOCK_HEADER}"
              TextTransformations:
                - Priority: 0
                  Type: NONE
              PositionalConstraint: EXACTLY
          VisibilityConfig:
            SampledRequestsEnabled: true
            CloudWatchMetricsEnabled: true
            MetricName: BlockHeaderRuleMetric
Outputs:
  WebACLArn:
    Value: !GetAtt BlockWebACL.Arn
  WebACLId:
    Value: !GetAtt BlockWebACL.Id
"""
    outputs = _deploy_cfn(ctx, cfn, template)
    webacl_arn = outputs["WebACLArn"]
    webacl_id = outputs["WebACLId"]

    # AssociateWebACL transiently raises WAFUnavailableEntityException while a new stage or
    # WebACL propagates.
    _retry_on_unavailable(lambda: wafv2.associate_web_acl(WebACLArn=webacl_arn, ResourceArn=stage["stage_arn"]))
    ctx.on_cleanup(lambda: _safe_disassociate(wafv2, stage["stage_arn"]))

    resolved = wafv2.get_web_acl_for_resource(ResourceArn=stage["stage_arn"])
    assert resolved["WebACL"]["ARN"] == webacl_arn, (
        f"stage resolved to WebACL {resolved['WebACL']['ARN']!r}, expected {webacl_arn!r}"
    )

    fetched = wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id)
    rule_actions = {r["Name"]: list(r["Action"].keys())[0] for r in fetched["WebACL"]["Rules"]}
    assert rule_actions["BlockHeaderRule"] == "Block", (
        f"BlockHeaderRule action is {rule_actions['BlockHeaderRule']!r}, expected 'Block'"
    )

    # Association propagation can take from seconds to minutes, so poll for the block.
    blocked_status, blocked_body = _poll_until_status(
        stage["invoke_url"], {_BLOCK_HEADER: _BLOCK_VALUE}, 403, timeout_s=150, interval_s=5
    )
    assert blocked_status == 403, f"matching request got {blocked_status}, expected 403"
    assert blocked_body == '{"message":"Forbidden"}', f"expected WAF's default block body, got {blocked_body!r}"

    allowed_status, _ = _http_status(stage["invoke_url"], {})
    assert allowed_status == 200, f"non-matching request got {allowed_status}, expected 200"


def _create_apigw_stage(ctx, apigw):
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-wafapi-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": ""},
    )
    stage_name = "prod"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    region = ctx.region
    return {
        "api_id": api_id,
        "stage_arn": f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stage_name}",
        "invoke_url": f"{ctx.rest_api_url(api_id, stage_name)}/",
    }


def _deploy_cfn(ctx, cfn, template_body):
    stack_name = ctx.unique_name("sim2real-wafcfn-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _safe_disassociate(wafv2, resource_arn):
    try:
        wafv2.disassociate_web_acl(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


def _retry_on_unavailable(fn, timeout_s=120, interval_s=5):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # botocore.exceptions.ClientError
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code != "WAFUnavailableEntityException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _http_status(url, headers):
    """(status, body) of a GET, or (None, None) while the endpoint does not answer."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()
    except urllib.error.URLError:
        return None, None


def _poll_until_status(url, headers, expected_status, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        last = _http_status(url, headers)
        if last[0] == expected_status:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"expected HTTP {expected_status}, last observed {last[0]}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
