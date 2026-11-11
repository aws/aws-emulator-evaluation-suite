"""deploy-webacl-cfn-enforces-default-block-action."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deploy-webacl-cfn-enforces-default-block-action"
GROUP = "deploy"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed WebACL with DefaultAction Block, associated in the same stack,
    turns a 200-serving API into one returning 403.
    """
    api = _create_mock_rest_api(ctx)

    # Positive control: without a WebACL the mock API serves 200.
    baseline = _poll_until(
        lambda: _http_status(api["invoke_url"]), lambda s: s == 200, timeout_s=60.0
    )
    assert baseline == 200, f"expected the unprotected mock API to serve 200, got {baseline}"

    stack_name = ctx.unique_name("sim2real-behav-block-")
    metric_name = stack_name.replace("-", "")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"ResourceArn": {"Type": "String"}},
            "Resources": {
                "BlockAllWebACL": {
                    "Type": "AWS::WAFv2::WebACL",
                    "Properties": {
                        "Name": stack_name,
                        "Scope": "REGIONAL",
                        "DefaultAction": {"Block": {}},
                        "Rules": [],
                        "VisibilityConfig": {
                            "SampledRequestsEnabled": True,
                            "CloudWatchMetricsEnabled": True,
                            "MetricName": metric_name,
                        },
                    },
                },
                "Association": {
                    "Type": "AWS::WAFv2::WebACLAssociation",
                    "Properties": {
                        "ResourceArn": {"Ref": "ResourceArn"},
                        "WebACLArn": {"Fn::GetAtt": "BlockAllWebACL.Arn"},
                    },
                },
            },
            "Outputs": {
                "WebACLArn": {"Value": {"Fn::GetAtt": "BlockAllWebACL.Arn"}},
            },
        }
    )
    stack = _deploy_cfn(ctx, template, {"ResourceArn": api["resource_arn"]})
    web_acl_arn = stack["outputs"]["WebACLArn"]

    got = ctx.client("wafv2").get_web_acl(ARN=web_acl_arn)["WebACL"]
    assert "Block" in got["DefaultAction"], (
        f"expected the CFN-deployed WebACL's DefaultAction to be Block, got {got['DefaultAction']!r}"
    )

    blocked = _poll_until(
        lambda: _http_status(api["invoke_url"]), lambda s: s == 403, timeout_s=120.0
    )
    assert blocked == 403, f"expected the default-Block WebACL to reject traffic, got {blocked}"


def _http_status(url: str, timeout: float = 10.0) -> int | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as err:
        return err.code
    except (urllib.error.URLError, ConnectionError, TimeoutError):
        return None


def _poll_until(probe, predicate, timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _create_mock_rest_api(ctx) -> dict:
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-api-")
    api = apigw.create_rest_api(
        name=name, endpointConfiguration={"types": ["REGIONAL"]}, tags={"sim2real": CHECK}
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
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
    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    invoke_url = f"{ctx.rest_api_url(api_id, stage_name)}/"
    resource_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}/stages/{stage_name}"
    return {"api_id": api_id, "invoke_url": invoke_url, "resource_arn": resource_arn}


def _deploy_cfn(ctx, template_body: str, parameters: dict[str, str] | None = None) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    params = [
        {"ParameterKey": k, "ParameterValue": v} for k, v in (parameters or {}).items()
    ]

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=params,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    return {"stack_name": stack_name, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
