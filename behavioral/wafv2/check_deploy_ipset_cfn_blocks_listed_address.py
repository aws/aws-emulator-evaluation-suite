"""deploy-ipset-cfn-blocks-listed-address."""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deploy-ipset-cfn-blocks-listed-address"
GROUP = "deploy"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed IPSet referenced by a Block rule in a WebACL from the same stack
    blocks real requests from its listed addresses once the WebACL is associated with an API.
    """
    api = _create_mock_rest_api(ctx)
    baseline = _poll_until(
        lambda: _http_status(api["invoke_url"]), lambda s: s == 200, timeout_s=60.0
    )
    assert baseline == 200, f"expected the mock API to serve 200 before any WAF is attached, got {baseline}"

    # The mock API echoes the source address it sees. A caller behind a NAT pool can egress
    # from several addresses, so every address observed across a few requests is blocked.
    source_ips = sorted(_source_ips(api["invoke_url"]))
    if not source_ips:
        raise AssertionError(
            "the mock API never echoed an IPv4 source address -- an IP-block test needs the "
            "exact source address the protected resource sees"
        )
    blocked_cidrs = [f"{ip}/32" for ip in source_ips]

    stack_name = ctx.unique_name("sim2real-behav-ipblk-")
    metric_name = stack_name.replace("-", "")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "ResourceArn": {"Type": "String"},
                "BlockedCidrs": {"Type": "CommaDelimitedList"},
            },
            "Resources": {
                "BlockedIPSet": {
                    "Type": "AWS::WAFv2::IPSet",
                    "Properties": {
                        "Name": f"{stack_name}-ipset",
                        "Scope": "REGIONAL",
                        "IPAddressVersion": "IPV4",
                        "Addresses": {"Ref": "BlockedCidrs"},
                    },
                },
                "WebACL": {
                    "Type": "AWS::WAFv2::WebACL",
                    "Properties": {
                        "Name": stack_name,
                        "Scope": "REGIONAL",
                        "DefaultAction": {"Allow": {}},
                        "Rules": [
                            {
                                "Name": "block-listed-ips",
                                "Priority": 0,
                                "Action": {"Block": {}},
                                "Statement": {
                                    "IPSetReferenceStatement": {
                                        "Arn": {"Fn::GetAtt": "BlockedIPSet.Arn"}
                                    }
                                },
                                "VisibilityConfig": {
                                    "SampledRequestsEnabled": True,
                                    "CloudWatchMetricsEnabled": True,
                                    "MetricName": f"{metric_name}rule",
                                },
                            }
                        ],
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
                        "WebACLArn": {"Fn::GetAtt": "WebACL.Arn"},
                    },
                },
            },
            "Outputs": {
                "WebACLArn": {"Value": {"Fn::GetAtt": "WebACL.Arn"}},
                "IPSetArn": {"Value": {"Fn::GetAtt": "BlockedIPSet.Arn"}},
            },
        }
    )
    stack = _deploy_cfn(
        ctx, template, {"ResourceArn": api["resource_arn"], "BlockedCidrs": ",".join(blocked_cidrs)}
    )

    ip_set = ctx.client("wafv2").get_ip_set(
        Name=f"{stack_name}-ipset", Scope="REGIONAL", Id=stack["outputs"]["IPSetArn"].split("/")[-1]
    )["IPSet"]
    assert sorted(ip_set["Addresses"]) == blocked_cidrs, (
        f"expected the CFN-deployed IPSet to contain exactly {blocked_cidrs}, got {ip_set['Addresses']}"
    )

    blocked = _poll_until(
        lambda: _http_status(api["invoke_url"]), lambda s: s == 403, timeout_s=120.0
    )
    assert blocked == 403, f"expected requests from {source_ips} to be blocked, got {blocked}"


_IPV4 = re.compile(r"\d{1,3}(\.\d{1,3}){3}")


def _source_ips(url: str, samples: int = 8) -> set[str]:
    """The IPv4 source addresses the API reports for this caller's requests."""
    seen = set()
    for _ in range(samples):
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                ip = resp.read().decode().strip()
        except (urllib.error.URLError, ConnectionError, TimeoutError):  # a lost sample only narrows the set
            continue
        if _IPV4.fullmatch(ip):
            seen.add(ip)
    return seen


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
    api = apigw.create_rest_api(name=name, endpointConfiguration={"types": ["REGIONAL"]})
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
        responseTemplates={"application/json": "$context.identity.sourceIp"},
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
