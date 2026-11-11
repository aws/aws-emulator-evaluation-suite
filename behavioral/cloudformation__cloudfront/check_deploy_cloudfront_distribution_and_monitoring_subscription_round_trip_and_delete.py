"""deploy-cloudfront-distribution-and-monitoring-subscription-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudfront-distribution-and-monitoring-subscription-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudfront"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_DEPLOY_S = 900.0  # a distribution's create and its edge propagation take minutes on CloudFront
_SUBSCRIPTION_GONE = ("NoSuchMonitoringSubscription", "The monitoring subscription does not exist.")
_DISTRIBUTION_GONE = ("NoSuchDistribution", "The specified distribution does not exist.")


def _template(comment, cache_policy_id, with_subscription=True):
    resources = {
        "ContentBucket": {"Type": "AWS::S3::Bucket", "Properties": {
            "BucketEncryption": {"ServerSideEncryptionConfiguration": [
                {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "BlockPublicPolicy": True,
                "IgnorePublicAcls": True, "RestrictPublicBuckets": True},
        }},
        "Distribution": {"Type": "AWS::CloudFront::Distribution", "Properties": {
            "Tags": [{"Key": "sim2real-dist", "Value": comment}],
            "DistributionConfig": {
                "Enabled": False,  # never serves: nothing internet-facing for the run
                "Comment": comment,
                "DefaultCacheBehavior": {"TargetOriginId": "s3origin",
                                         "ViewerProtocolPolicy": "redirect-to-https",
                                         "CachePolicyId": cache_policy_id},
                "Origins": [{"Id": "s3origin",
                             "DomainName": {"Fn::GetAtt": ["ContentBucket", "RegionalDomainName"]},
                             "S3OriginConfig": {"OriginAccessIdentity": ""}}],
            },
        }},
    }
    outputs = {
        "DistributionId": {"Value": {"Ref": "Distribution"}},
        "DistributionDomainName": {"Value": {"Fn::GetAtt": ["Distribution", "DomainName"]}},
        "BucketDomainName": {"Value": {"Fn::GetAtt": ["ContentBucket", "RegionalDomainName"]}},
    }
    if with_subscription:
        resources["MonitoringSubscription"] = {
            "Type": "AWS::CloudFront::MonitoringSubscription", "Properties": {
                "DistributionId": {"Ref": "Distribution"},
                "MonitoringSubscription": {"RealtimeMetricsSubscriptionConfig": {
                    "RealtimeMetricsSubscriptionStatus": "Enabled"}},
            }}
        outputs["MonitoringSubscriptionId"] = {"Value": {"Ref": "MonitoringSubscription"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _cf_items(call, list_key, **kw):
    """Every ``Items`` entry of a CloudFront Marker-paged list, across every page."""
    items, marker = [], None
    while True:
        page = call(**kw, **({"Marker": marker} if marker else {}))[list_key]
        items += page.get("Items", [])
        marker = page.get("NextMarker")
        if not marker:
            return items


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Distribution and its MonitoringSubscription read back, then delete child-first.

    Ref and GetAtts match the ListDistributions entry and every templated property reads back; an
    update dropping the subscription removes it while the distribution answers, then the stack.
    """
    cfn = ctx.client("cloudformation")
    cf = ctx.client("cloudfront")
    stack = ctx.unique_name("sim2real-cf-dist-")
    comment = f"sim2real {stack}"
    managed = [p["CachePolicy"] for p in _cf_items(cf.list_cache_policies, "CachePolicyList",
                                                   Type="managed")
               if p["CachePolicy"]["CachePolicyConfig"]["Name"] == "Managed-CachingOptimized"]
    assert len(managed) == 1, f"precondition: managed CachingOptimized policy {managed!r}"
    cache_policy_id = managed[0]["Id"]

    stack_id = create_stack(ctx, cfn, stack, _template(comment, cache_policy_id))
    status = wait_stack(cfn, stack_id, timeout_s=_DEPLOY_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    dist_id = out["DistributionId"]
    assert out["MonitoringSubscriptionId"] == dist_id, (
        f"MonitoringSubscription Ref {out['MonitoringSubscriptionId']!r} != distribution {dist_id!r}"
    )

    listed = [(d["Id"], d["DomainName"]) for d in _cf_items(cf.list_distributions, "DistributionList")
              if d["Comment"] == comment]
    assert listed == [(dist_id, out["DistributionDomainName"])], (
        f"ListDistributions with comment {comment!r}: {listed!r}; outputs {out!r}"
    )
    dist = cf.get_distribution(Id=dist_id)["Distribution"]
    config = dist["DistributionConfig"]
    behavior = config["DefaultCacheBehavior"]
    origins = config["Origins"]["Items"]
    got = (config["Enabled"], config["Comment"], behavior["TargetOriginId"],
           behavior["ViewerProtocolPolicy"], behavior["CachePolicyId"],
           [(o["Id"], o["DomainName"], o["S3OriginConfig"]["OriginAccessIdentity"]) for o in origins])
    want = (False, comment, "s3origin", "redirect-to-https", cache_policy_id,
            [("s3origin", out["BucketDomainName"], "")])
    assert got == want, f"distribution config {got!r}, expected {want!r}"
    tag_list = cf.list_tags_for_resource(Resource=dist["ARN"])["Tags"]["Items"]
    tag_values = {t["Key"]: t["Value"] for t in tag_list if not t["Key"].startswith("aws:")}
    assert tag_values == {"sim2real": stack, "sim2real-dist": comment}, f"tags {tag_values!r}"
    sub = cf.get_monitoring_subscription(DistributionId=dist_id)["MonitoringSubscription"]
    assert sub == {"RealtimeMetricsSubscriptionConfig": {
        "RealtimeMetricsSubscriptionStatus": "Enabled"}}, f"monitoring subscription {sub!r}"

    # Child first: the update drops only the subscription; its own NotFound while the
    # distribution (same ARN) still answers.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(comment, cache_policy_id, with_subscription=False))
    status = wait_stack(cfn, stack_id, timeout_s=_DEPLOY_S)
    assert status == "UPDATE_COMPLETE", f"subscription-dropping update ended {status!r}"
    kept_arn = cf.get_distribution(Id=dist_id)["Distribution"]["ARN"]
    assert kept_arn == dist["ARN"], f"ARN {kept_arn!r} after the update, was {dist['ARN']!r}"
    expect_error(lambda: cf.get_monitoring_subscription(DistributionId=dist_id), *_SUBSCRIPTION_GONE)

    delete_stack(cfn, stack_id)
    expect_error(lambda: cf.get_distribution(Id=dist_id), *_DISTRIBUTION_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
