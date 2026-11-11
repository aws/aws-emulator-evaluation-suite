"""deploy-emrcontainers-jobtemplate-invalid-releaselabel-rejected-and-rolled-back."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-emrcontainers-jobtemplate-invalid-releaselabel-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "emr-containers"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

_BAD_RELEASE_LABEL = "emr 6.15.0 bad label"
_RELEASE_LABEL_PATTERN = r"^([\.\-_/A-Za-z0-9]+|\$\{[a-zA-Z]\w*\})$"
_RELEASE_LABEL = "emr-6.15.0-latest"
# AWS's documented example bucket name; the template is never run, so nothing reads it.
_ENTRY_POINT = "s3://amzn-s3-demo-bucket/scripts/main.py"
_SPARK_PARAMS = "--conf spark.executor.instances=2"


def _template(name, release_label):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecutionRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]}}},
            "JobTemplate": {"Type": "AWS::EMRContainers::JobTemplate", "Properties": {
                "Name": name,
                "JobTemplateData": {
                    "ExecutionRoleArn": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                    "ReleaseLabel": release_label,
                    "JobDriver": {"SparkSubmitJobDriver": {
                        "EntryPoint": _ENTRY_POINT, "SparkSubmitParameters": _SPARK_PARAMS}},
                },
                "Tags": [{"Key": "sim2real-jt", "Value": name}],
            }},
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["ExecutionRole", "Arn"]}},
            "JobTemplateArn": {"Value": {"Ref": "JobTemplate"}},
            "JobTemplateId": {"Value": {"Fn::GetAtt": ["JobTemplate", "Id"]}},
            "JobTemplateCreatedBy": {"Value": {"Fn::GetAtt": ["JobTemplate", "CreatedBy"]}},
        },
    })


def _listed(emrc, name):
    return [t for t in paginate(emrc, "list_job_templates", "templates") if t["name"] == name]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation EMR on EKS job template whose ReleaseLabel breaks its pattern is refused.

    Early validation names the property path and no template exists, while the same template
    with a valid ReleaseLabel deploys.
    """
    cf = ctx.client("cloudformation")
    emrc = ctx.client("emr-containers")
    good_name = ctx.unique_name("sim2real-behav-jt-ok-")
    bad_name = ctx.unique_name("sim2real-behav-jt-bad-")

    # Positive control: the same template with a valid ReleaseLabel.
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-behav-jt-ok-stack-"),
                           _template(good_name, _RELEASE_LABEL), Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    control = [(t["arn"], t["jobTemplateData"]["releaseLabel"]) for t in _listed(emrc, good_name)]
    assert control == [(stack_outputs(cf, good_id)["JobTemplateArn"], _RELEASE_LABEL)], (
        f"control job template reads {control!r}"
    )

    # The one bad property: ReleaseLabel violates the type's pattern.
    bad_id = create_stack(ctx, cf, ctx.unique_name("sim2real-behav-jt-bad-stack-"),
                          _template(bad_name, _BAD_RELEASE_LABEL), Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = [r for r in validation_rows(cf, bad_id) if r[3] == "FAIL"]
    want = [("JobTemplate", "PROPERTY_VALIDATION", "FAILED", "FAIL",
             f"Property value [{_BAD_RELEASE_LABEL}] does not match pattern: "
             f"{_RELEASE_LABEL_PATTERN}",
             "/Resources/JobTemplate/Properties/JobTemplateData/ReleaseLabel")]
    assert rows == want, f"validation rows {rows!r}, expected {want!r}"

    # Rollback absence through EMR Containers, BEFORE this check deletes the stack.
    assert _listed(emrc, bad_name) == [], f"rejected template listed: {_listed(emrc, bad_name)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
