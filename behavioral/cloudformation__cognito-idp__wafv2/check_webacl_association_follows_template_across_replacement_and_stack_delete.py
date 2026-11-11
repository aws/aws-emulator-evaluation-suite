"""webacl-association-follows-template-across-replacement-and-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-association-follows-template-across-replacement-and-stack-delete"
GROUP = "deploy-cfn-wafv2-association"
SERVICES = ["cloudformation", "cognito-idp", "wafv2"]

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _describe(cf, name):
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError:
        return None


def _wait_terminal(cf, name, *, timeout_s=600, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        stack = _describe(cf, name)
        status = None if stack is None else stack["StackStatus"]
        if stack is not None and status in _TERMINAL_STATES:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {name} did not reach a terminal state within {timeout_s}s (last={status!r})"
            )
        time.sleep(interval_s)


def _wait_deleted(cf, name, *, timeout_s=600, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        stack = _describe(cf, name)
        if stack is None:
            return
        if stack["StackStatus"] not in _TERMINAL_STATES:
            if time.monotonic() >= deadline:
                raise AssertionError(f"stack {name} did not delete within {timeout_s}s")
            time.sleep(interval_s)
            continue
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        raise AssertionError(f"stack {name} left in {stack['StackStatus']!r} instead of deleting")


def _poll_until(fn, predicate, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed {last!r}")


def _outputs(cf, name):
    stack = _describe(cf, name)
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


_TRANSIENT_NO_ASSOCIATION = {"WAFNonexistentItemException", "WAFUnavailableEntityException"}


def _get_web_acl_for_resource(wafv2, resource_arn):
    """GetWebACLForResource, treating a propagation-lag exception as "no WebACL yet": AWS can
    raise WAFNonexistentItemException for a just-changed association until reads catch up."""
    try:
        return wafv2.get_web_acl_for_resource(ResourceArn=resource_arn).get("WebACL")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in _TRANSIENT_NO_ASSOCIATION:
            return None
        raise


def _visibility(metric):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": metric}


def _template(active_acl_logical_id):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Pool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {"UserPoolTags": {"sim2real": "xsvc-cfn-wafv2-assoc"}},
            },
            "AclA": {
                "Type": "AWS::WAFv2::WebACL",
                "Properties": {
                    "Name": {"Fn::Sub": "sim2real-xsvc-cfn-wafv2-${AWS::StackName}-a"},
                    "Scope": "REGIONAL",
                    "DefaultAction": {"Allow": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": {"Fn::Sub": "${AWS::StackName}AclA"},
                    },
                },
            },
            "AclB": {
                "Type": "AWS::WAFv2::WebACL",
                "Properties": {
                    "Name": {"Fn::Sub": "sim2real-xsvc-cfn-wafv2-${AWS::StackName}-b"},
                    "Scope": "REGIONAL",
                    "DefaultAction": {"Allow": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": {"Fn::Sub": "${AWS::StackName}AclB"},
                    },
                },
            },
            "Assoc": {
                "Type": "AWS::WAFv2::WebACLAssociation",
                "Properties": {
                    "ResourceArn": {"Fn::GetAtt": "Pool.Arn"},
                    "WebACLArn": {"Fn::GetAtt": f"{active_acl_logical_id}.Arn"},
                },
            },
        },
        "Outputs": {
            "PoolArn": {"Value": {"Fn::GetAtt": "Pool.Arn"}},
            "AclAArn": {"Value": {"Fn::GetAtt": "AclA.Arn"}},
            "AclBArn": {"Value": {"Fn::GetAtt": "AclB.Arn"}},
            "AssocRef": {"Value": {"Ref": "Assoc"}},
        },
    })


@tags("axis:happy-path", "cap:c2", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN WebACLAssociation on a user pool has a composite 'ResourceArn|WebACLArn' Ref, is
    replaced when the template switches WebACL (old one disassociated, only the new one listed),
    and the pool reports no WebACL after the stack is deleted."""
    cf = ctx.client("cloudformation")
    wafv2 = ctx.client("wafv2")

    stack = ctx.unique_name("sim2real-xsvc-cfn-wafv2-assoc-")

    cf.create_stack(StackName=stack, TemplateBody=_template("AclA"))
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack))
    created = _wait_terminal(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )

    out1 = _outputs(cf, stack)
    pool_arn = out1["PoolArn"]
    acl_a_arn = out1["AclAArn"]
    acl_b_arn = out1["AclBArn"]
    expected_ref_a = f"{pool_arn}|{acl_a_arn}"
    assert out1["AssocRef"] == expected_ref_a, (
        f"expected Ref(Assoc) to be the composite 'ResourceArn|WebACLArn' {expected_ref_a!r}, "
        f"got {out1['AssocRef']!r}"
    )

    physical_a = cf.describe_stack_resource(StackName=stack, LogicalResourceId="Assoc")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    assert physical_a == expected_ref_a, (
        f"expected DescribeStackResource PhysicalResourceId {expected_ref_a!r}, got {physical_a!r}"
    )

    observed_a = _poll_until(
        lambda: _get_web_acl_for_resource(wafv2, pool_arn),
        lambda w: w is not None,
    )
    assert observed_a["ARN"] == acl_a_arn, (
        f"expected GetWebACLForResource to reflect AclA {acl_a_arn!r} after CREATE_COMPLETE, "
        f"observed {observed_a['ARN']!r}"
    )

    # ResourceArn and WebACLArn are both createOnly and the composite primaryIdentifier, so
    # switching to AclB must replace the association, not update it in place.
    cf.update_stack(StackName=stack, TemplateBody=_template("AclB"))
    updated = _wait_terminal(cf, stack)
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"expected UPDATE_COMPLETE, got {updated['StackStatus']!r}: {updated.get('StackStatusReason')!r}"
    )

    out2 = _outputs(cf, stack)
    expected_ref_b = f"{pool_arn}|{acl_b_arn}"
    assert out2["AssocRef"] == expected_ref_b, (
        f"expected the replaced association's Ref to be {expected_ref_b!r} after switching to "
        f"AclB, got {out2['AssocRef']!r}"
    )
    assert out2["PoolArn"] == pool_arn and out2["AclAArn"] == acl_a_arn and out2["AclBArn"] == acl_b_arn, (
        "the Pool/AclA/AclB resources themselves must be untouched by the association replacement"
    )

    observed_b = _poll_until(
        lambda: _get_web_acl_for_resource(wafv2, pool_arn),
        lambda w: w is not None and w["ARN"] == acl_b_arn,
    )
    assert observed_b["ARN"] == acl_b_arn, (
        f"expected GetWebACLForResource to reflect AclB {acl_b_arn!r} after the replacing update, "
        f"observed {observed_b['ARN']!r}"
    )

    resources_for_a = _poll_until(
        lambda: wafv2.list_resources_for_web_acl(
            WebACLArn=acl_a_arn, ResourceType="COGNITO_USER_POOL"
        )["ResourceArns"],
        lambda arns: pool_arn not in arns,
    )
    assert pool_arn not in resources_for_a, (
        f"the OLD association (AclA -> pool) must be cleaned up by the replacement; "
        f"ListResourcesForWebACL(AclA) still contains {pool_arn!r} in {resources_for_a!r}"
    )
    resources_for_b = wafv2.list_resources_for_web_acl(
        WebACLArn=acl_b_arn, ResourceType="COGNITO_USER_POOL"
    )["ResourceArns"]
    assert resources_for_b == [pool_arn], (
        f"expected ListResourcesForWebACL(AclB) to contain exactly the pool {pool_arn!r}, "
        f"got {resources_for_b!r}"
    )

    cf.delete_stack(StackName=stack)
    _wait_deleted(cf, stack)

    final = _poll_until(
        lambda: _get_web_acl_for_resource(wafv2, pool_arn),
        lambda w: w is None,
    )
    assert final is None, (
        f"expected GetWebACLForResource(pool) to report no WebACL after DeleteStack, "
        f"observed {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
