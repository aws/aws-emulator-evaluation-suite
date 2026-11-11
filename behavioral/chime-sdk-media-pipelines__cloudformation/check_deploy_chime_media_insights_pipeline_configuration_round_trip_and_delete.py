"""deploy-chime-media-insights-pipeline-configuration-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-chime-media-insights-pipeline-configuration-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["chime-sdk-media-pipelines", "cloudformation"]

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

_CONFIG_GONE = ("NotFoundException", "Unable to find the requested identifier")


def _list_configs(chime) -> list[dict]:
    """Every configuration over all NextToken pages; botocore models no paginator for it."""
    out, kw = [], {}
    while True:
        page = chime.list_media_insights_pipeline_configurations(**kw)
        out += page["MediaInsightsPipelineConfigurations"]
        if not page.get("NextToken"):
            return out
        kw["NextToken"] = page["NextToken"]


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Chime::MediaInsightsPipelineConfiguration (an S3
    recording sink) reads back through chime-sdk-media-pipelines with the template's own name,
    role and sink destination; deleting the stack removes it, which Chime then refuses by ARN.
    """
    cf = ctx.client("cloudformation")
    chime = ctx.client("chime-sdk-media-pipelines")

    stack_name = ctx.unique_name("sim2real-behav-cfn-micfg-")
    config_name = ctx.unique_name("sim2real-behav-micfg-")

    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "mediapipelines.chime.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    access_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:GetBucketPolicy"],
            "Resource": [
                {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}"},
                {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}/*"},
            ],
        }],
    }
    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket"},
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust,
                    "Policies": [{"PolicyName": "sim2real-access", "PolicyDocument": access_policy}],
                },
            },
            "Config": {
                "Type": "AWS::Chime::MediaInsightsPipelineConfiguration",
                "Properties": {
                    "MediaInsightsPipelineConfigurationName": config_name,
                    "ResourceAccessRoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                    "Elements": [{
                        "Type": "S3RecordingSink",
                        "S3RecordingSinkConfiguration": {
                            "Destination": {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}"},
                            "RecordingFileFormat": "Wav",
                        },
                    }],
                },
            },
        },
        "Outputs": {
            "ConfigArn": {"Value": {"Ref": "Config"}},
            "ConfigId": {"Value": {"Fn::GetAtt": ["Config", "MediaInsightsPipelineConfigurationId"]}},
            "BucketName": {"Value": {"Ref": "Bucket"}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
        },
    })

    stack_id = create_stack(ctx, cf, stack_name, template, Capabilities=["CAPABILITY_IAM"])
    created = wait_stack(cf, stack_id, timeout_s=400.0)
    assert created == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {created!r}"

    outputs = stack_outputs(cf, stack_id)
    config_arn = outputs["ConfigArn"]
    bucket_name = outputs["BucketName"]
    partition = stack_id.split(":")[1]
    want_arn = (
        f"arn:{partition}:chime:{ctx.region}:{ctx.account}:media-insights-pipeline-configuration/"
        f"{config_name}"
    )
    assert config_arn == want_arn, f"Ref Config is {config_arn!r}, expected {want_arn!r}"
    listed = [
        c for c in _list_configs(chime) if c["MediaInsightsPipelineConfigurationName"] == config_name
    ]
    assert [c["MediaInsightsPipelineConfigurationArn"] for c in listed] == [config_arn], (
        f"expected one listed configuration named {config_name!r} with Ref's ARN, got {listed!r}"
    )

    fetched = chime.get_media_insights_pipeline_configuration(Identifier=config_arn)[
        "MediaInsightsPipelineConfiguration"
    ]
    assert fetched["MediaInsightsPipelineConfigurationName"] == config_name, (
        f"expected Name {config_name!r}, Chime reports "
        f"{fetched['MediaInsightsPipelineConfigurationName']!r}"
    )
    assert fetched["ResourceAccessRoleArn"] == outputs["RoleArn"], (
        f"expected ResourceAccessRoleArn {outputs['RoleArn']!r}, Chime reports "
        f"{fetched['ResourceAccessRoleArn']!r}"
    )
    assert fetched["MediaInsightsPipelineConfigurationId"] == outputs["ConfigId"], (
        f"GetAtt ConfigId was {outputs['ConfigId']!r}, Chime's own Id is "
        f"{fetched['MediaInsightsPipelineConfigurationId']!r}"
    )
    assert len(fetched["Elements"]) == 1, (
        f"expected exactly 1 Elements entry, Chime reports {len(fetched['Elements'])}: "
        f"{fetched['Elements']!r}"
    )
    element = fetched["Elements"][0]
    assert element["Type"] == "S3RecordingSink", (
        f"expected element Type 'S3RecordingSink', Chime reports {element['Type']!r}"
    )
    sink_config = element["S3RecordingSinkConfiguration"]
    want_destination = f"arn:{partition}:s3:::{bucket_name}"
    assert sink_config["Destination"] == want_destination, (
        f"expected S3 sink Destination {want_destination!r}, Chime reports "
        f"{sink_config['Destination']!r}"
    )
    assert sink_config["RecordingFileFormat"] == "Wav", (
        f"expected RecordingFileFormat 'Wav', Chime reports {sink_config['RecordingFileFormat']!r}"
    )

    delete_stack(cf, stack_id)
    expect_error(lambda: chime.get_media_insights_pipeline_configuration(Identifier=config_arn),
                 *_CONFIG_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
