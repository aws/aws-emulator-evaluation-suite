"""deploy-workflow-and-workflow-version-via-cloudformation-reaches-create-complete."""
from __future__ import annotations

import io
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-workflow-and-workflow-version-via-cloudformation-reaches-create-complete"
GROUP = "deploy"
SERVICES = ["cloudformation", "omics"]

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

_WDL = """version 1.0
workflow Sim2RealProbe {
  input {
    String greeting = "hello"
  }
  call Greet { input: greeting = greeting }
  output {
    String out = Greet.out
  }
}
task Greet {
  input {
    String greeting
  }
  command {
    echo "~{greeting}" > out.txt
  }
  output {
    String out = read_string("out.txt")
  }
  runtime {
    docker: "public.ecr.aws/amazonlinux/amazonlinux:2023"
  }
}
"""


def _template(workflow_name, definition_uri, version_name=None):
    workflow = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Sim2RealWorkflow:
    Type: AWS::Omics::Workflow
    Properties:
      Name: {workflow_name}
      Engine: WDL
      DefinitionUri: {definition_uri}
      Main: main.wdl
"""
    if version_name is None:
        return workflow + """Outputs:
  WorkflowId:
    Value: !Ref Sim2RealWorkflow
"""
    return workflow + f"""  Sim2RealWorkflowVersion:
    Type: AWS::Omics::WorkflowVersion
    Properties:
      WorkflowId: !Ref Sim2RealWorkflow
      VersionName: {version_name}
      Engine: WDL
      DefinitionUri: {definition_uri}
      Main: main.wdl
Outputs:
  WorkflowId:
    Value: !Ref Sim2RealWorkflow
  WorkflowArn:
    Value: !GetAtt Sim2RealWorkflow.Arn
  WorkflowVersionArn:
    Value: !Ref Sim2RealWorkflowVersion
  WorkflowVersionStatus:
    Value: !GetAtt Sim2RealWorkflowVersion.Status
  WorkflowVersionUuid:
    Value: !GetAtt Sim2RealWorkflowVersion.Uuid
"""


def _workflow_ids_named(omics, name):
    """Ids of every private workflow named ``name``, read through every page."""
    items = paginate(omics, "list_workflows", "items", name=name, type="PRIVATE")
    return [w["id"] for w in items if w.get("name") == name]


def _empty_bucket(s3, bucket_name):
    """Delete every object version and delete marker in bucket_name."""
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket_name):
        objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get("Versions", [])]
        objs += [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs})


def _create_bucket(ctx, s3, bucket_name):
    """Create a region-located, tagged S3 bucket; its empty-then-delete cleanup is registered first."""

    def _delete_bucket():
        try:
            _empty_bucket(s3, bucket_name)
            s3.delete_bucket(Bucket=bucket_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchBucket":
                return
            raise

    ctx.on_cleanup(_delete_bucket)
    kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket_name}]}
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloudFormation AWS::Omics::Workflow and WorkflowVersion are real HealthOmics resources: Ref,
    GetAtt, engine and entrypoint read back; removing the version deletes only it, and deleting
    the stack deletes the workflow."""
    cf = ctx.client("cloudformation")
    omics = ctx.client("omics")
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-xsvc-wf-bkt-")
    workflow_name = ctx.unique_name("sim2real-xsvc-workflow-")
    version_name = "sim2real-v1"

    _create_bucket(ctx, s3, bucket_name)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("main.wdl", _WDL)
    key = "defs/main.zip"
    s3.put_object(Bucket=bucket_name, Key=key, Body=buf.getvalue())
    definition_uri = f"s3://{bucket_name}/{key}"

    stack_id = create_stack(ctx, cf, ctx.unique_name("sim2real-xsvc-stk-"),
                            _template(workflow_name, definition_uri, version_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    outputs = stack_outputs(cf, stack_id)
    workflow_id = outputs["WorkflowId"]

    listed = _workflow_ids_named(omics, workflow_name)
    assert listed == [workflow_id], (
        f"expected Ref {workflow_id!r} to be the one workflow HealthOmics lists under "
        f"{workflow_name!r}, got {listed!r}"
    )
    wf_described = omics.get_workflow(id=listed[0])
    assert wf_described["arn"] == outputs["WorkflowArn"], (
        f"expected GetAtt Arn {outputs['WorkflowArn']!r}, got {wf_described['arn']!r}"
    )
    assert wf_described["name"] == workflow_name, f"expected name {workflow_name!r}, got {wf_described['name']!r}"
    assert wf_described["engine"] == "WDL", f"expected engine 'WDL', got {wf_described['engine']!r}"
    assert wf_described["main"] == "main.wdl", f"expected main 'main.wdl', got {wf_described['main']!r}"

    wfv_described = omics.get_workflow_version(workflowId=workflow_id, versionName=version_name)
    assert wfv_described["arn"] == outputs["WorkflowVersionArn"], (
        f"Ref {outputs['WorkflowVersionArn']!r} does not equal the workflow version arn "
        f"{wfv_described['arn']!r}"
    )
    assert wfv_described["versionName"] == version_name, (
        f"expected versionName {version_name!r}, got {wfv_described['versionName']!r}"
    )
    assert wfv_described["engine"] == "WDL", f"expected engine 'WDL', got {wfv_described['engine']!r}"
    assert wfv_described["main"] == "main.wdl", (
        f"expected the version's main 'main.wdl', got {wfv_described['main']!r}"
    )
    got_attrs = (outputs["WorkflowVersionStatus"], outputs["WorkflowVersionUuid"])
    want_attrs = (wfv_described["status"], wfv_described["uuid"])
    assert got_attrs == want_attrs, (
        f"GetAtt (Status, Uuid) of the version {got_attrs!r} must equal HealthOmics' own "
        f"{want_attrs!r}"
    )

    # The version's own delete: update it out of the stack while its workflow stays.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(workflow_name, definition_uri))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE, got {status!r}"

    version_not_found = ("ResourceNotFoundException",
                         f"Workflow {workflow_id} with version name {version_name} not found")
    expect_error(lambda: omics.get_workflow_version(workflowId=workflow_id, versionName=version_name),
                 *version_not_found)
    assert omics.get_workflow(id=workflow_id)["id"] == workflow_id, (
        "the workflow must outlive the removal of its version"
    )

    delete_stack(cf, stack_id)
    workflow_not_found = ("ResourceNotFoundException", f"Workflow {workflow_id} not found")
    expect_error(lambda: omics.get_workflow(id=workflow_id), *workflow_not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
