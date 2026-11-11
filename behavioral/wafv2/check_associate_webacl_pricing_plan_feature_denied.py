"""associate-webacl-pricing-plan-feature-denied."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-webacl-pricing-plan-feature-denied"
GROUP = "overly-permissive"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateWebACL rejects a nonexistent WebACLArn and leaves the resource unassociated.

    The refusal is WAFNonexistentItemException with the exact message; associating a real web ACL
    with the same API Gateway stage succeeds before and after the rejected attempt.
    """
    wafv2 = ctx.client("wafv2")
    api = _create_mock_rest_api(ctx, ["check"])

    webacl_name = ctx.unique_name("sim2real-wafv2-webacl-")
    real_webacl = wafv2.create_web_acl(
        Name=webacl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": webacl_name,
        },
        Tags=[{"Key": "sim2real", "Value": webacl_name}],
    )["Summary"]
    real_webacl_id = real_webacl["Id"]
    ctx.on_cleanup(
        lambda: wafv2.delete_web_acl(
            Name=webacl_name, Scope="REGIONAL", Id=real_webacl_id, LockToken=real_webacl["LockToken"]
        )
    )

    account_id = ctx.account

    # Positive control FIRST, same file: prove the ResourceArn itself is valid and
    # already resolvable by AssociateWebACL. A freshly-deployed API Gateway stage can
    # take a short while to become resolvable to WAF (WAFUnavailableEntityException:
    # "AWS WAF couldn't retrieve the resource") -- poll through that propagation
    # window rather than asserting immediately.
    _retry_unavailable(lambda: wafv2.associate_web_acl(WebACLArn=real_webacl["ARN"], ResourceArn=api["stage_arn"]))
    ctx.on_cleanup(lambda: wafv2.disassociate_web_acl(ResourceArn=api["stage_arn"]))
    associated_id = _associated_webacl_id(wafv2, api["stage_arn"])
    assert associated_id == real_webacl_id, f"expected {real_webacl_id!r} associated, got {associated_id!r}"
    wafv2.disassociate_web_acl(ResourceArn=api["stage_arn"])
    cleared_id = _associated_webacl_id(wafv2, api["stage_arn"])
    assert cleared_id is None, f"expected no association after disassociate, got {cleared_id!r}"

    fake_id = "00000000-0000-4000-8000-000000000000"
    fake_name = ctx.unique_name("sim2real-wafv2-nope-")
    fake_webacl_arn = f"arn:aws:wafv2:{ctx.region}:{account_id}:regional/webacl/{fake_name}/{fake_id}"

    code, message = _error(lambda: wafv2.associate_web_acl(WebACLArn=fake_webacl_arn, ResourceArn=api["stage_arn"]))
    assert code == "WAFNonexistentItemException", f"got {code!r} instead"
    assert message == "AWS WAF couldn’t perform the operation because your resource doesn’t exist.", message

    # Effect absent: the failed attempt left the resource unassociated.
    post_reject_id = _associated_webacl_id(wafv2, api["stage_arn"])
    assert post_reject_id is None, f"expected no association after rejected attempt, got {post_reject_id!r}"

    # Re-associating with the real web ACL still succeeds after the rejected attempt.
    _retry_unavailable(lambda: wafv2.associate_web_acl(WebACLArn=real_webacl["ARN"], ResourceArn=api["stage_arn"]))
    restored_id = _associated_webacl_id(wafv2, api["stage_arn"])
    assert restored_id == real_webacl_id, f"expected {real_webacl_id!r} associated after restore, got {restored_id!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A call that succeeds raises:
    an emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _retry_unavailable(fn, *, timeout_s=180.0, interval_s=10.0):
    """AssociateWebACL can transiently report WAFUnavailableEntityException ("AWS WAF
    couldn't retrieve the resource") for a resource that was only just created --
    eventual-consistency propagation, not a real rejection. Poll through it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] != "WAFUnavailableEntityException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _associated_webacl_id(wafv2, resource_arn):
    try:
        resp = wafv2.get_web_acl_for_resource(ResourceArn=resource_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "WAFNonexistentItemException":
            return None
        raise
    webacl = resp.get("WebACL")
    return webacl.get("Id") if webacl else None


def _create_mock_rest_api(ctx, paths):
    apigw = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-wafv2-api-")
    api = apigw.create_rest_api(name=api_name, tags={"sim2real": api_name})
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
