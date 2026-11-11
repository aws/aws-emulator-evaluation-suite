"""deploy-sagemaker-featuregroup-and-pipeline-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sagemaker-featuregroup-and-pipeline-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "sagemaker"]

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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


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

def _template(fg_name: str, pipeline_name: str) -> str:
    pipeline_def = json.dumps({
        "Version": "2020-12-01",
        "Steps": [{"Name": "FailStep", "Type": "Fail",
                   "Arguments": {"ErrorMessage": "sim2real never-executed pipeline"}}],
    })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "sagemaker.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                },
            },
            "FeatureGroup": {
                "Type": "AWS::SageMaker::FeatureGroup",
                "Properties": {
                    "FeatureGroupName": fg_name,
                    "RecordIdentifierFeatureName": "id",
                    "EventTimeFeatureName": "ts",
                    "FeatureDefinitions": [
                        {"FeatureName": "id", "FeatureType": "String"},
                        {"FeatureName": "ts", "FeatureType": "String"},
                    ],
                    "OnlineStoreConfig": {"EnableOnlineStore": True},
                },
            },
            "Pipeline": {
                "Type": "AWS::SageMaker::Pipeline",
                "Properties": {
                    "PipelineName": pipeline_name,
                    "PipelineDefinition": {"PipelineDefinitionBody": pipeline_def},
                    "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "FeatureGroupRef": {"Value": {"Ref": "FeatureGroup"}},
            "FeatureGroupCreationTime": {"Value": {"Fn::GetAtt": ["FeatureGroup", "CreationTime"]}},
            "FeatureGroupStatus": {"Value": {"Fn::GetAtt": ["FeatureGroup", "FeatureGroupStatus"]}},
            "PipelineRef": {"Value": {"Ref": "Pipeline"}},
        },
    })


def _epoch(value) -> float:
    """Parse a SageMaker timestamp, either an ISO-ish string or a boto3 datetime, to epoch seconds."""
    if isinstance(value, datetime):
        return value.timestamp()
    text = value.strip()
    if text.replace(".", "", 1).isdigit():
        return float(text)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp()


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed SageMaker FeatureGroup and Pipeline are both real at SageMaker:
    Ref, every declared GetAtt and the template's own properties read back through SageMaker's
    DescribeFeatureGroup/DescribePipeline, and deleting the stack removes both from SageMaker.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sagemaker-featuregroup.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sagemaker-pipeline.html
    """
    cf = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")
    stack_name = ctx.unique_name("sim2real-behav-cfn-sm-")
    fg_name = ctx.unique_name("sim2real-behav-fg-")
    pipeline_name = ctx.unique_name("sim2real-behav-pl-")

    stack_id = create_stack(ctx, cf, stack_name, _template(fg_name, pipeline_name),
                            Capabilities=["CAPABILITY_IAM"])
    created = wait_stack(cf, stack_id, timeout_s=600.0)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )

    outputs = stack_outputs(cf, stack_id)

    # ---- FeatureGroup: Ref is the FeatureGroupName; GetAtt CreationTime and FeatureGroupStatus
    # and the template's own properties all read back through SageMaker's own API.
    assert outputs["FeatureGroupRef"] == fg_name, (
        f"Ref FeatureGroup was {outputs['FeatureGroupRef']!r}, expected the template's "
        f"FeatureGroupName {fg_name!r}"
    )
    fg = sm.describe_feature_group(FeatureGroupName=fg_name)
    assert fg["FeatureGroupName"] == fg_name, (
        f"expected DescribeFeatureGroup to report name {fg_name!r}, got {fg['FeatureGroupName']!r}"
    )
    assert fg["FeatureGroupStatus"] == "Created", (
        f"expected FeatureGroupStatus 'Created' once CREATE_COMPLETE, SageMaker reports "
        f"{fg['FeatureGroupStatus']!r}"
    )
    assert outputs["FeatureGroupStatus"] == fg["FeatureGroupStatus"], (
        f"GetAtt FeatureGroup.FeatureGroupStatus was {outputs['FeatureGroupStatus']!r}, "
        f"SageMaker's own value is {fg['FeatureGroupStatus']!r}"
    )
    got_time = _epoch(outputs["FeatureGroupCreationTime"])
    want_time = _epoch(fg["CreationTime"])
    assert abs(got_time - want_time) < 1.0, (
        f"GetAtt FeatureGroup.CreationTime was {outputs['FeatureGroupCreationTime']!r} "
        f"(epoch {got_time}), SageMaker's own CreationTime is {fg['CreationTime']!r} "
        f"(epoch {want_time})"
    )
    assert fg["RecordIdentifierFeatureName"] == "id", (
        f"expected RecordIdentifierFeatureName 'id', got {fg['RecordIdentifierFeatureName']!r}"
    )
    assert fg["EventTimeFeatureName"] == "ts", (
        f"expected EventTimeFeatureName 'ts', got {fg['EventTimeFeatureName']!r}"
    )
    got_defs = {(d["FeatureName"], d["FeatureType"]) for d in fg["FeatureDefinitions"]}
    want_defs = {("id", "String"), ("ts", "String")}
    assert got_defs == want_defs, f"expected FeatureDefinitions {want_defs!r}, got {got_defs!r}"
    assert fg["OnlineStoreConfig"]["EnableOnlineStore"] is True, (
        f"expected OnlineStoreConfig.EnableOnlineStore True, got {fg['OnlineStoreConfig']!r}"
    )

    # ---- Pipeline: Ref is the PipelineName; RoleArn and the pipeline definition read back
    # through SageMaker's own API. AWS::SageMaker::Pipeline declares no GetAtt attribute.
    assert outputs["PipelineRef"] == pipeline_name, (
        f"Ref Pipeline was {outputs['PipelineRef']!r}, expected the template's "
        f"PipelineName {pipeline_name!r}"
    )
    pipeline = sm.describe_pipeline(PipelineName=pipeline_name)
    assert pipeline["PipelineName"] == pipeline_name, (
        f"expected DescribePipeline to report name {pipeline_name!r}, got {pipeline['PipelineName']!r}"
    )
    assert pipeline["RoleArn"] == outputs["RoleArn"], (
        f"expected Pipeline.RoleArn {outputs['RoleArn']!r}, SageMaker reports {pipeline['RoleArn']!r}"
    )
    want_definition = json.loads(json.loads(_template(fg_name, pipeline_name))
                                  ["Resources"]["Pipeline"]["Properties"]["PipelineDefinition"]
                                  ["PipelineDefinitionBody"])
    assert json.loads(pipeline["PipelineDefinition"]) == want_definition, (
        f"expected the declared pipeline definition {want_definition!r}, "
        f"got {json.loads(pipeline['PipelineDefinition'])!r}"
    )

    delete_stack(cf, stack_id)

    fg_not_found = ("ResourceNotFound",
                    f"Resource Not Found: Amazon SageMaker can't find a FeatureGroup with name {fg_name}")
    expect_error(lambda: sm.describe_feature_group(FeatureGroupName=fg_name), *fg_not_found)

    partition = stack_id.split(":")[1]
    pipeline_arn = f"arn:{partition}:sagemaker:{ctx.region}:<account>:pipeline/{pipeline_name}"
    want = ("ResourceNotFound", f"Pipeline '{pipeline_arn}' does not exist.")
    try:
        result = sm.describe_pipeline(PipelineName=pipeline_name)
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], masked(exc.response["Error"].get("Message", ""),
                                                     ctx.account))
    else:
        raise AssertionError(f"DescribePipeline answered after the stack delete: {result!r}")
    assert got == want, f"reading the deleted pipeline answered {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
