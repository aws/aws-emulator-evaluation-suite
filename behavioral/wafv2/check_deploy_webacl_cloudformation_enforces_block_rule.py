"""deploy-webacl-cloudformation-enforces-block-rule."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "deploy-webacl-cloudformation-enforces-block-rule"
GROUP = "deploy"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c2", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A WebACL with a Block rule deployed by CloudFormation and associated with an API Gateway stage answers the
    matching path 403 with body {"message":"Forbidden"} and another path 200, and GetSampledRequests reports the blocked
    request with Action BLOCK.
    """
    wafv2 = ctx.client("wafv2")
    api = _create_mock_rest_api(ctx, ["blocked", "ok"])

    webacl_name = ctx.unique_name("sim2real-wafv2-webacl-")
    block_metric = "BlockPathRuleMetric"
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "WebACL": {
                "Type": "AWS::WAFv2::WebACL",
                "Properties": {
                    "Name": webacl_name,
                    "Scope": "REGIONAL",
                    "DefaultAction": {"Allow": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": webacl_name,
                    },
                    "Rules": [
                        {
                            "Name": "BlockPathRule",
                            "Priority": 0,
                            "Action": {"Block": {}},
                            "Statement": {
                                "ByteMatchStatement": {
                                    "SearchString": "blocked",
                                    "FieldToMatch": {"UriPath": {}},
                                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                                    "PositionalConstraint": "CONTAINS",
                                }
                            },
                            "VisibilityConfig": {
                                "SampledRequestsEnabled": True,
                                "CloudWatchMetricsEnabled": True,
                                "MetricName": block_metric,
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "sim2real", "Value": CHECK},
                        {"Key": "sim2real:managed", "Value": "true"},
                    ],
                },
            }
        },
        "Outputs": {"WebACLArn": {"Value": {"Fn::GetAtt": "WebACL.Arn"}}},
    }
    stack_name = ctx.unique_name("sim2real-wafv2-stack-")
    outputs = _deploy_cfn(ctx, template, stack_name)
    webacl_arn = outputs["WebACLArn"]
    webacl_id = webacl_arn.split("/")[-1]

    got = wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id)
    assert got["WebACL"]["Name"] == webacl_name, f"expected WebACL name {webacl_name!r}, got {got['WebACL']['Name']!r}"
    assert got["WebACL"]["Rules"][0]["Action"] == {"Block": {}}, (
        f"expected the CFN-declared rule's Action to be Block, got {got['WebACL']['Rules'][0]['Action']!r}"
    )

    # A freshly-deployed API Gateway stage can take a short while to become
    # resolvable to WAF (WAFUnavailableEntityException: "AWS WAF couldn't retrieve
    # the resource") -- poll through that propagation window rather than asserting
    # immediately. Web ACL/association changes can then take "a few seconds to a
    # number of minutes" to propagate -- see the AssociateWebACL doc's "Temporary
    # inconsistencies during updates" note. Poll for the effect rather than asserting
    # immediately.
    _retry_unavailable(lambda: wafv2.associate_web_acl(WebACLArn=webacl_arn, ResourceArn=api["stage_arn"]))
    ctx.on_cleanup(lambda: wafv2.disassociate_web_acl(ResourceArn=api["stage_arn"]))

    blocked_status, blocked_body = _poll_until(
        lambda: _http_get(api["invoke_url"] + "/blocked"),
        lambda answer: answer[0] == 403,
        timeout_s=150.0,
        interval_s=5.0,
    )
    assert blocked_status == 403, f"expected /blocked to be WAF-blocked, got {blocked_status}"
    assert blocked_body == '{"message":"Forbidden"}', f"expected WAF's default block body, got {blocked_body!r}"

    ok_status, _ = _http_get(api["invoke_url"] + "/ok")
    assert ok_status == 200, f"expected /ok to pass through unblocked, got {ok_status}"

    # GetSampledRequests returns a statistical SAMPLE, not a guaranteed log of every
    # matched request -- a single blocked call may not be captured. Generate a burst
    # of additional blocked requests to raise the odds of a sample landing, then poll
    # with a generous timeout for the sample to become queryable.
    for _ in range(25):
        _http_get(api["invoke_url"] + "/blocked")

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=2)
    samples = _poll_until(
        lambda: wafv2.get_sampled_requests(
            WebAclArn=webacl_arn,
            RuleMetricName=block_metric,
            Scope="REGIONAL",
            TimeWindow={"StartTime": start, "EndTime": end},
            MaxItems=500,
        )["SampledRequests"],
        lambda samples: len(samples) > 0,
        timeout_s=240.0,
        interval_s=15.0,
    )
    assert samples, "no sampled requests recorded for the block rule"
    assert samples[0]["Action"] == "BLOCK", f"expected sampled request Action BLOCK, got {samples[0]['Action']!r}"


def _create_mock_rest_api(ctx, paths):
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-wafv2-api-"),
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    for path in paths:
        resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart=path)["id"]
        apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
        apigw.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            type="MOCK",
            requestTemplates={"application/json": '{"statusCode": 200}'},
        )
        apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
        apigw.put_integration_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            statusCode="200",
            responseTemplates={"application/json": ""},
        )
    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    region = ctx.region
    return {
        "api_id": api_id,
        "stage_arn": f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stage_name}",
        "invoke_url": ctx.rest_api_url(api_id, stage_name),
    }


def _deploy_cfn(ctx, template, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _http_get(url, headers=None, timeout=10):
    """(status, body) of a GET, or (None, None) while the endpoint does not answer."""
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except urllib.error.URLError:
        return None, None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _retry_unavailable(fn, *, timeout_s=180.0, interval_s=10.0):
    """AssociateWebACL can transiently report WAFUnavailableEntityException ("AWS WAF
    couldn't retrieve the resource") for a resource that was only just created --
    eventual-consistency propagation, not a real rejection. Poll through it."""
    import botocore.exceptions

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "WAFUnavailableEntityException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
