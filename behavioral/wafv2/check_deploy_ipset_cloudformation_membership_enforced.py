"""deploy-ipset-cloudformation-membership-enforced."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deploy-ipset-cloudformation-membership-enforced"
GROUP = "deploy"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed IPSet holding one CIDR, referenced by a WebACL rule, is enforced on live traffic: a
    forwarded IP inside the CIDR gets 403 with body {"message":"Forbidden"}, one outside 200.
    """
    wafv2 = ctx.client("wafv2")
    api = _create_mock_rest_api(ctx, ["check"])

    ipset_name = ctx.unique_name("sim2real-wafv2-ipset-")
    member_cidr = "203.0.113.0/24"  # RFC 5737 TEST-NET-3
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "IPSet": {
                "Type": "AWS::WAFv2::IPSet",
                "Properties": {
                    "Name": ipset_name,
                    "Scope": "REGIONAL",
                    "IPAddressVersion": "IPV4",
                    "Addresses": [member_cidr],
                },
            }
        },
        "Outputs": {
            "IPSetArn": {"Value": {"Fn::GetAtt": "IPSet.Arn"}},
            "IPSetId": {"Value": {"Fn::GetAtt": "IPSet.Id"}},
        },
    }
    stack_name = ctx.unique_name("sim2real-wafv2-ipset-stack-")
    outputs = _deploy_cfn(ctx, template, stack_name)
    ipset_arn = outputs["IPSetArn"]
    ipset_id = outputs["IPSetId"]

    got_ipset = wafv2.get_ip_set(Name=ipset_name, Scope="REGIONAL", Id=ipset_id)
    assert got_ipset["IPSet"]["Addresses"] == [member_cidr], (
        f"expected the CFN-deployed IPSet to contain exactly [{member_cidr}], "
        f"got {got_ipset['IPSet']['Addresses']}"
    )

    webacl_name = ctx.unique_name("sim2real-wafv2-webacl-")
    created = wafv2.create_web_acl(
        Name=webacl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        Rules=[
            {
                "Name": "BlockIPSetRule",
                "Priority": 0,
                "Action": {"Block": {}},
                "Statement": {
                    "IPSetReferenceStatement": {
                        "ARN": ipset_arn,
                        "IPSetForwardedIPConfig": {
                            "HeaderName": "X-Forwarded-For",
                            "FallbackBehavior": "NO_MATCH",
                            "Position": "FIRST",
                        },
                    }
                },
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "BlockIPSetRuleMetric",
                },
            }
        ],
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": webacl_name,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Summary"]
    webacl_arn = created["ARN"]
    ctx.on_cleanup(
        lambda: wafv2.delete_web_acl(
            Name=webacl_name, Scope="REGIONAL", Id=created["Id"], LockToken=created["LockToken"]
        )
    )

    # A fresh API Gateway stage can briefly be unresolvable to WAF (WAFUnavailableEntityException).
    _retry_unavailable(lambda: wafv2.associate_web_acl(WebACLArn=webacl_arn, ResourceArn=api["stage_arn"]))
    ctx.on_cleanup(lambda: wafv2.disassociate_web_acl(ResourceArn=api["stage_arn"]))

    # Association propagation: see AssociateWebACL's "Temporary inconsistencies during
    # updates" note (up to a few minutes). Poll for the effect.
    member_status, member_body = _poll_until(
        lambda: _http_get(api["invoke_url"] + "/check", headers={"X-Forwarded-For": "203.0.113.10"}),
        lambda answer: answer[0] == 403,
        timeout_s=150.0,
        interval_s=5.0,
    )
    assert member_status == 403, f"expected an IP inside {member_cidr} to be blocked, got {member_status}"
    assert member_body == '{"message":"Forbidden"}', f"expected WAF's default block body, got {member_body!r}"

    non_member_status, _ = _http_get(api["invoke_url"] + "/check", headers={"X-Forwarded-For": "198.51.100.10"})
    assert non_member_status == 200, f"expected an IP outside the set to be allowed, got {non_member_status}"


def _create_mock_rest_api(ctx, paths):
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-wafv2-api-"), tags={"sim2real": CHECK})
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    last = (None, None)
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _retry_unavailable(fn, *, timeout_s=180.0, interval_s=10.0):
    """Retry fn through WAFUnavailableEntityException, which AssociateWebACL reports transiently
    for a just-created resource."""
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
