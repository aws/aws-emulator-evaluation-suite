"""stackset-invalid-name-pattern-rejected-then-succeeds-with-a-valid-name."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "stackset-invalid-name-pattern-rejected-then-succeeds-with-a-valid-name"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


# ---- Check-specific: the template, then run(). ----

_REJECTED = [(
    "SS", "PROPERTY_VALIDATION", "FAILED", "FAIL",
    "Property value [<name>] does not match pattern: ^[a-zA-Z][a-zA-Z0-9\\-]{0,127}$",
    "/Resources/SS/Properties/StackSetName",
)]


def _inner_template(topic_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": topic_name}},
        },
        "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
    })


def _template(stack: str, stackset_name: str, exec_role_name: str, topic_name: str) -> str:
    """Least-privilege self-managed roles: the exec role manages only the instance stack and topic."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "AdminRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "cloudformation.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "AssumeExecRole",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "sts:AssumeRole",
                                "Resource": {"Fn::Sub":
                                             "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/"
                                             f"{exec_role_name}"},
                            }],
                        },
                    }],
                },
            },
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": exec_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"AWS": {"Fn::GetAtt": ["AdminRole", "Arn"]}},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "ManageInstanceStackAndTopic",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": "sns:*", "Resource": {"Fn::Sub":
                                 f"arn:${{AWS::Partition}}:sns:*:${{AWS::AccountId}}:{topic_name}"}},
                                {"Effect": "Allow", "Action": "cloudformation:*", "Resource": {
                                    "Fn::Sub": "arn:${AWS::Partition}:cloudformation:*:"
                                               f"${{AWS::AccountId}}:stack/StackSet-{stackset_name}-*"}},
                            ],
                        },
                    }],
                },
            },
            "SS": {
                "Type": "AWS::CloudFormation::StackSet",
                "DependsOn": ["AdminRole", "ExecRole"],
                "Properties": {
                    "StackSetName": stackset_name,
                    "PermissionModel": "SELF_MANAGED",
                    "AdministrationRoleARN": {"Fn::GetAtt": ["AdminRole", "Arn"]},
                    "ExecutionRoleName": exec_role_name,
                    "TemplateBody": _inner_template(topic_name),
                    # The instance stack and its topic carry the run's sim2real tag.
                    "Tags": [{"Key": "sim2real", "Value": stack}],
                    "StackInstancesGroup": [{
                        "DeploymentTargets": {"Accounts": [{"Ref": "AWS::AccountId"}]},
                        "Regions": [{"Ref": "AWS::Region"}],
                    }],
                },
            },
        },
        "Outputs": {
            "StackSetId": {"Value": {"Ref": "SS"}},
            "AdminRoleArn": {"Value": {"Fn::GetAtt": ["AdminRole", "Arn"]}},
        },
    })


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    rows = [r["PhysicalResourceId"] for r in paginate(
        cfn, "list_stack_resources", "StackResourceSummaries", StackName=stack_id)
        if r["LogicalResourceId"] == logical_id]
    assert len(rows) == 1, f"stack {stack_id!r} resource {logical_id!r}: {rows!r}"
    return rows[0]


def _instance_topic(ctx, cfn, sns, stackset_name, stack):
    """The single CURRENT instance in this account and region, and its tagged SNS topic ARN."""
    instances = paginate(cfn, "list_stack_instances", "Summaries", StackSetName=stackset_name)
    got = [(i["Account"], i["Region"], i["Status"], i["StackInstanceStatus"]["DetailedStatus"])
           for i in instances]
    assert got == [(ctx.account, ctx.region, "CURRENT", "SUCCEEDED")], f"stack instances {got!r}"
    topic_arn = _physical_id(cfn, instances[0]["StackId"], "Topic")
    attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert attrs["TopicArn"] == topic_arn, f"SNS TopicArn {attrs['TopicArn']!r} != {topic_arn!r}"
    topic_tags = {t["Key"]: t["Value"] for t in
                  sns.list_tags_for_resource(ResourceArn=topic_arn).get("Tags", [])
                  if not t["Key"].startswith("aws:")}
    assert topic_tags == {"sim2real": stack}, f"instance topic tags {topic_tags!r}"
    return topic_arn


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A StackSetName violating the declared pattern (it must start with a letter) fails early
    property validation at its exact path, and the same template with only the name valid
    deploys a real stack instance whose tagged SNS topic exists."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    exec_role_name = ctx.unique_name("sim2real-behav-cfn-ssbadexec-")
    topic_name = ctx.unique_name("sim2real-behav-cfn-ssbadtopic-")
    bad_name = "1" + ctx.unique_name("sim2real-behav-cfn-ssbadname-")
    good_name = ctx.unique_name("sim2real-behav-cfn-ssgoodname-")

    bad_stack = ctx.unique_name("sim2real-behav-cfn-ssbadname-")
    bad_id = create_stack(ctx, cfn, bad_stack,
                          _template(bad_stack, bad_name, exec_role_name, topic_name),
                          Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = [(*r[:4], masked(r[4] or "", ctx.account, bad_name), r[5])
            for r in validation_rows(cfn, bad_id) if r[3] == "FAIL"]
    assert rows == _REJECTED, f"VALIDATION_ERROR rows {rows!r}, expected {_REJECTED!r}"
    # Rollback absence through CloudFormation's stack-set read, before this check deletes.
    listed = [s["StackSetName"] for s in paginate(cfn, "list_stack_sets", "Summaries")]
    assert bad_name not in listed, f"ListStackSets lists the rejected name {bad_name!r}"

    # Positive control: the same template with only the StackSetName valid.
    good_stack = ctx.unique_name("sim2real-behav-cfn-ssgoodname-")
    good_id = create_stack(ctx, cfn, good_stack,
                           _template(good_stack, good_name, exec_role_name, topic_name),
                           Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    _instance_topic(ctx, cfn, sns, good_name, good_stack)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
