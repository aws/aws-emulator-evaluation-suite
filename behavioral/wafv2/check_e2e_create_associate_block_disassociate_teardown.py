"""e2e-create-associate-block-disassociate-teardown."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-create-associate-block-disassociate-teardown"
GROUP = "e2e"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An IPSet-backed Block WebACL associated with an API stage shows in GetWebACLForResource and
    ListResourcesForWebACL; after disassociate and delete, both Gets are WAFNonexistentItem."""
    wafv2 = ctx.client("wafv2")
    apigw = ctx.client("apigateway")

    stage = _create_apigw_stage(ctx, apigw)

    ipset_name = ctx.unique_name("sim2real-waf-e2e-ipset-")
    ipset = wafv2.create_ip_set(
        Name=ipset_name,
        Scope="REGIONAL",
        IPAddressVersion="IPV4",
        Addresses=["203.0.113.0/24"],
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    ipset_id = ipset["Summary"]["Id"]
    ipset_arn = ipset["Summary"]["ARN"]
    ctx.on_cleanup(lambda: _safe_delete_ip_set(wafv2, ipset_name, "REGIONAL", ipset_id))

    webacl_name = ctx.unique_name("sim2real-waf-e2e-acl-")
    # CreateWebACL transiently raises WAFUnavailableEntityException while the new IPSet propagates.
    webacl = _retry_on_unavailable(
        lambda: wafv2.create_web_acl(
            Name=webacl_name,
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": webacl_name,
            },
            Rules=[
                {
                    "Name": "BlockKnownIPs",
                    "Priority": 0,
                    "Action": {"Block": {}},
                    "Statement": {"IPSetReferenceStatement": {"ARN": ipset_arn}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "BlockKnownIPsMetric",
                    },
                }
            ],
            Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
        )
    )
    webacl_id = webacl["Summary"]["Id"]
    webacl_arn = webacl["Summary"]["ARN"]
    ctx.on_cleanup(lambda: _safe_delete_web_acl(wafv2, webacl_name, "REGIONAL", webacl_id))

    _retry_on_unavailable(lambda: wafv2.associate_web_acl(WebACLArn=webacl_arn, ResourceArn=stage["stage_arn"]))
    ctx.on_cleanup(lambda: _safe_disassociate(wafv2, stage["stage_arn"]))

    resolved = wafv2.get_web_acl_for_resource(ResourceArn=stage["stage_arn"])
    assert resolved["WebACL"]["ARN"] == webacl_arn, (
        f"GetWebACLForResource resolved {resolved['WebACL']['ARN']!r} for the stage, "
        f"expected the associated ACL {webacl_arn!r}"
    )

    resources = _poll_until_resource_listed(wafv2, webacl_arn, stage["stage_arn"])
    assert stage["stage_arn"] in resources, (
        f"stage {stage['stage_arn']!r} never appeared in ListResourcesForWebACL for "
        f"{webacl_arn!r}; last seen={resources!r}"
    )

    wafv2.disassociate_web_acl(ResourceArn=stage["stage_arn"])

    _poll_until_no_association(wafv2, stage["stage_arn"])

    current_acl = wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id)
    wafv2.delete_web_acl(
        Name=webacl_name, Scope="REGIONAL", Id=webacl_id, LockToken=current_acl["LockToken"]
    )
    current_ipset = wafv2.get_ip_set(Name=ipset_name, Scope="REGIONAL", Id=ipset_id)
    wafv2.delete_ip_set(
        Name=ipset_name, Scope="REGIONAL", Id=ipset_id, LockToken=current_ipset["LockToken"]
    )

    webacl_gone_code, webacl_gone_message = _error(
        lambda: wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id)
    )
    assert webacl_gone_code == "WAFNonexistentItemException", (
        f"GetWebACL on the deleted ACL {webacl_id!r} returned {webacl_gone_code!r}, "
        f"expected WAFNonexistentItemException"
    )
    assert webacl_gone_message == "AWS WAF couldn’t perform the operation because your resource doesn’t exist.", webacl_gone_message
    ipset_gone_code, ipset_gone_message = _error(
        lambda: wafv2.get_ip_set(Name=ipset_name, Scope="REGIONAL", Id=ipset_id)
    )
    assert ipset_gone_code == "WAFNonexistentItemException", (
        f"GetIPSet on the deleted set {ipset_id!r} returned {ipset_gone_code!r}, "
        f"expected WAFNonexistentItemException"
    )
    assert ipset_gone_message == "AWS WAF couldn’t perform the operation because your resource doesn’t exist.", ipset_gone_message


def _create_apigw_stage(ctx, apigw):
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-wafapi-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
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


def _error(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _safe_disassociate(wafv2, resource_arn):
    try:
        wafv2.disassociate_web_acl(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


def _retry_on_unavailable(fn, timeout_s=240, interval_s=8):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "WAFUnavailableEntityException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _safe_delete_web_acl(wafv2, name, scope, id_):
    try:
        current = wafv2.get_web_acl(Name=name, Scope=scope, Id=id_)
        wafv2.delete_web_acl(Name=name, Scope=scope, Id=id_, LockToken=current["LockToken"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


def _safe_delete_ip_set(wafv2, name, scope, id_):
    try:
        current = wafv2.get_ip_set(Name=name, Scope=scope, Id=id_)
        wafv2.delete_ip_set(Name=name, Scope=scope, Id=id_, LockToken=current["LockToken"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


def _poll_until_no_association(wafv2, resource_arn, timeout_s=90, interval_s=5):
    # GetWebACLForResource returns a null WebACL, not an error, once nothing is associated.
    deadline = time.monotonic() + timeout_s
    last_webacl = "unchecked"
    while time.monotonic() < deadline:
        resp = wafv2.get_web_acl_for_resource(ResourceArn=resource_arn)
        last_webacl = resp.get("WebACL")
        if last_webacl is None:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"resource still resolves an associated WebACL after DisassociateWebACL; last WebACL={last_webacl}"
    )


def _poll_until_resource_listed(wafv2, webacl_arn, resource_arn, timeout_s=180, interval_s=10):
    deadline = time.monotonic() + timeout_s
    last_resources = []
    while time.monotonic() < deadline:
        last_resources = wafv2.list_resources_for_web_acl(
            WebACLArn=webacl_arn, ResourceType="API_GATEWAY"
        ).get("ResourceArns", [])
        if resource_arn in last_resources:
            return last_resources
        time.sleep(interval_s)
    raise AssertionError(
        f"resource {resource_arn} never appeared in ListResourcesForWebACL; last seen={last_resources}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
