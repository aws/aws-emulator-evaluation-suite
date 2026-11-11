"""deploy-stackset-self-managed-provisions-a-real-stack-instance-then-removes-it."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-stackset-self-managed-provisions-a-real-stack-instance-then-removes-it"
GROUP = "resource-existence"
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
                                             f"arn:${{AWS::Partition}}:iam::*:role/{exec_role_name}"},
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


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::CloudFormation::StackSet reads back with every declared property and
    really provisions a stack instance whose tagged SNS topic exists at SNS; deleting the stack
    removes the stack set and the topic, not just the CFN-reported resource."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    stack = ctx.unique_name("sim2real-behav-cfn-ss-")
    stackset_name = ctx.unique_name("sim2real-behav-cfn-ss-")
    exec_role_name = ctx.unique_name("sim2real-behav-cfn-ssexec-")
    topic_name = ctx.unique_name("sim2real-behav-cfn-sstopic-")

    stack_id = create_stack(ctx, cfn, stack,
                            _template(stack, stackset_name, exec_role_name, topic_name),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    listed = [s["StackSetId"] for s in paginate(cfn, "list_stack_sets", "Summaries",
                                                Status="ACTIVE")
              if s["StackSetName"] == stackset_name]
    assert listed == [outputs["StackSetId"]], (
        f"ListStackSets {listed!r} for Ref {outputs['StackSetId']!r}"
    )
    stack_set = cfn.describe_stack_set(StackSetName=stackset_name)["StackSet"]
    got = {k: stack_set.get(k) for k in ("Status", "PermissionModel", "AdministrationRoleARN",
                                         "ExecutionRoleName")}
    want = {"Status": "ACTIVE", "PermissionModel": "SELF_MANAGED",
            "AdministrationRoleARN": outputs["AdminRoleArn"], "ExecutionRoleName": exec_role_name}
    assert got == want, f"DescribeStackSet {got!r}, expected {want!r}"
    got = json.loads(stack_set["TemplateBody"])
    assert got == json.loads(_inner_template(topic_name)), f"stack set TemplateBody {got!r}"
    got = {t["Key"]: t["Value"] for t in stack_set.get("Tags", [])}
    assert got == {"sim2real": stack}, f"stack set tags {got!r}"
    topic_arn = _instance_topic(ctx, cfn, sns, stackset_name, stack)

    delete_stack(cfn, stack_id)
    gone = ("StackSetNotFoundException", f"StackSet {stackset_name} not found")
    expect_error(lambda: cfn.describe_stack_set(StackSetName=stackset_name), *gone)
    gone = ("NotFound", "Topic does not exist")
    expect_error(lambda: sns.get_topic_attributes(TopicArn=topic_arn), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
