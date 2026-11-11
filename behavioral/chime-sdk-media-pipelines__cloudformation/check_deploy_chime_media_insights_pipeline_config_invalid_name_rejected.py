"""deploy-chime-media-insights-pipeline-config-invalid-name-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-chime-media-insights-pipeline-config-invalid-name-rejected"
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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

_TYPE = "AWS::Chime::MediaInsightsPipelineConfiguration"
_NAME_PATTERN = "^[0-9a-zA-Z._-]+$"
_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)


def _template(config_name: str) -> str:
    """An S3 recording sink configuration with its own bucket and access role."""
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
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket"},
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust,
                    "Policies": [
                        {"PolicyName": "sim2real-access", "PolicyDocument": access_policy},
                    ],
                },
            },
            "Config": {
                "Type": _TYPE,
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
            "BucketName": {"Value": {"Ref": "Bucket"}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
        },
    })


def _create_stack(ctx, cf, stack_name: str, template: str) -> str:
    """CreateStack with the check's stack tag; its delete is registered before the call."""
    return create_stack(ctx, cf, stack_name, template, Capabilities=["CAPABILITY_IAM"])


def _list_configs(chime) -> list[dict]:
    """Every configuration over all NextToken pages; botocore models no paginator for it."""
    out, kw = [], {}
    while True:
        page = chime.list_media_insights_pipeline_configurations(**kw)
        out += page["MediaInsightsPipelineConfigurations"]
        if not page.get("NextToken"):
            return out
        kw["NextToken"] = page["NextToken"]


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A MediaInsightsPipelineConfigurationName outside Chime's naming pattern fails the type's
    property validation before provisioning and the stack creates nothing; the same template
    with a valid name deploys a configuration Chime reads back.
    """
    cf = ctx.client("cloudformation")
    chime = ctx.client("chime-sdk-media-pipelines")

    # ---- positive control: the same template with a valid name ----
    good_stack = ctx.unique_name("sim2real-behav-cfn-micfg-good-")
    good_name = ctx.unique_name("sim2real-behav-micfg-good-")
    good_id = _create_stack(ctx, cf, good_stack, _template(good_name))
    status = wait_stack(cf, good_id, timeout_s=400.0)
    assert status == "CREATE_COMPLETE", f"positive-control stack ended {status!r}"
    good_outputs = stack_outputs(cf, good_id)
    good_arn = good_outputs["ConfigArn"]
    listed = [c for c in _list_configs(chime)
              if c["MediaInsightsPipelineConfigurationName"] == good_name]
    assert [c["MediaInsightsPipelineConfigurationArn"] for c in listed] == [good_arn], (
        f"expected one listed configuration named {good_name!r} with Ref's ARN, got {listed!r}"
    )
    fetched = chime.get_media_insights_pipeline_configuration(Identifier=good_arn)[
        "MediaInsightsPipelineConfiguration"
    ]
    assert fetched["MediaInsightsPipelineConfigurationName"] == good_name, (
        f"expected Name {good_name!r}, Chime reports "
        f"{fetched['MediaInsightsPipelineConfigurationName']!r}"
    )
    assert fetched["ResourceAccessRoleArn"] == good_outputs["RoleArn"], (
        f"expected ResourceAccessRoleArn {good_outputs['RoleArn']!r}, Chime reports "
        f"{fetched['ResourceAccessRoleArn']!r}"
    )
    got_elements = [(e["Type"], e["S3RecordingSinkConfiguration"]["Destination"],
                     e["S3RecordingSinkConfiguration"]["RecordingFileFormat"])
                    for e in fetched["Elements"]]
    want_elements = [("S3RecordingSink",
                      f"arn:{good_id.split(':')[1]}:s3:::{good_outputs['BucketName']}", "Wav")]
    assert got_elements == want_elements, (
        f"expected the template's Elements {want_elements!r}, Chime reports {got_elements!r}"
    )

    # ---- negative: only the name differs ----
    bad_stack = ctx.unique_name("sim2real-behav-cfn-micfg-bad-")
    bad_name = ctx.unique_name("sim2real behav bad name ")
    bad_id = _create_stack(ctx, cf, bad_stack, _template(bad_name))
    status = wait_stack(cf, bad_id, timeout_s=400.0)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    reason = failed_reason(stack_events(cf, bad_id), bad_stack)
    assert reason == _STACK_REASON, (
        f"expected the one stack CREATE_FAILED reason {_STACK_REASON!r}, got {reason!r}"
    )
    found = validation_rows(cf, bad_id)
    want = [(
        "Config", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        f"Property value [{bad_name}] does not match pattern: {_NAME_PATTERN}",
        "/Resources/Config/Properties/MediaInsightsPipelineConfigurationName",
    )]
    assert found == want, f"expected VALIDATION_ERROR rows {want!r}, got {found!r}"

    resources = cf.describe_stack_resources(StackName=bad_id)["StackResources"]
    assert resources == [], f"the rejected stack should hold no resources, got {resources!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
