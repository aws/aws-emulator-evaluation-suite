"""webacl-association-unsupported-resource-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-association-unsupported-resource-type-rejected"
GROUP = "deploy-cfn-wafv2-association-rejected"
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


def _delete_queue_quietly(sqs, url):
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "AWS.SimpleQueueService.NonExistentQueue":
            raise


def _poll_until(fn, predicate, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed {last!r}")


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


def _association_template(resource_arn_value):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"WebACLArn": {"Type": "String"}},
        "Resources": {
            "Assoc": {
                "Type": "AWS::WAFv2::WebACLAssociation",
                "Properties": {
                    "ResourceArn": resource_arn_value,
                    "WebACLArn": {"Ref": "WebACLArn"},
                },
            },
        },
    })


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A WebACLAssociation naming a resource type WAFv2 does not front (an SQS queue) rolls the
    stack back, and the same WebACL still associates cleanly with a Cognito user pool."""
    cf = ctx.client("cloudformation")
    wafv2 = ctx.client("wafv2")
    sqs = ctx.client("sqs")
    cognito = ctx.client("cognito-idp")

    acl_name = ctx.unique_name("sim2real-xsvc-cfn-wafv2-neg-")
    acl = wafv2.create_web_acl(
        Name=acl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": acl_name.replace("-", ""),
        },
        Tags=[{"Key": "sim2real", "Value": "xsvc-cfn-wafv2-neg"}],
    )["Summary"]
    ctx.on_cleanup(lambda: wafv2.delete_web_acl(
        Name=acl["Name"], Scope="REGIONAL", Id=acl["Id"],
        LockToken=wafv2.get_web_acl(Name=acl["Name"], Scope="REGIONAL", Id=acl["Id"])["LockToken"],
    ))

    queue_name = ctx.unique_name("sim2real-xsvc-cfn-wafv2-neg-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real": "xsvc-cfn-wafv2-neg"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_quietly(sqs, queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    bad_stack = ctx.unique_name("sim2real-xsvc-cfn-wafv2-neg-bad-")
    cf.create_stack(
        StackName=bad_stack,
        TemplateBody=_association_template(queue_arn),
        Parameters=[{"ParameterKey": "WebACLArn", "ParameterValue": acl["ARN"]}],
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=bad_stack))
    bad_result = _wait_terminal(cf, bad_stack)
    assert bad_result["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"expected a WebACLAssociation naming an SQS queue to fail and roll back the stack as "
        f"ROLLBACK_COMPLETE, got {bad_result['StackStatus']!r}: {bad_result.get('StackStatusReason')!r}"
    )

    sqs_tags_after = sqs.list_queue_tags(QueueUrl=queue_url).get("Tags", {})
    assert sqs_tags_after.get("sim2real") == "xsvc-cfn-wafv2-neg", (
        "the queue itself must be untouched by the failed association attempt"
    )

    # Positive control on the same WebACL: proves the failure was resource-type validation,
    # not a broken WebACL.
    pool_name = ctx.unique_name("sim2real-xsvc-cfn-wafv2-neg-pool-")
    pool = cognito.create_user_pool(
        PoolName=pool_name, UserPoolTags={"sim2real": "xsvc-cfn-wafv2-neg"}
    )["UserPool"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool["Id"]))
    pool_arn = pool["Arn"]

    good_stack = ctx.unique_name("sim2real-xsvc-cfn-wafv2-neg-good-")
    cf.create_stack(
        StackName=good_stack,
        TemplateBody=_association_template(pool_arn),
        Parameters=[{"ParameterKey": "WebACLArn", "ParameterValue": acl["ARN"]}],
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=good_stack))
    good_result = _wait_terminal(cf, good_stack)
    assert good_result["StackStatus"] == "CREATE_COMPLETE", (
        f"expected the same WebACL to associate cleanly with a supported resource type (a "
        f"Cognito User Pool), got {good_result['StackStatus']!r}: {good_result.get('StackStatusReason')!r}"
    )

    observed = _poll_until(
        lambda: _get_web_acl_for_resource(wafv2, pool_arn),
        lambda w: w is not None,
    )
    assert observed["ARN"] == acl["ARN"], (
        f"expected the control association to reflect {acl['ARN']!r} at GetWebACLForResource, "
        f"observed {observed['ARN']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
