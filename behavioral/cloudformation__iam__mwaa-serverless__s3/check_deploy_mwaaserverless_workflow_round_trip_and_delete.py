"""deploy-mwaaserverless-workflow-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-mwaaserverless-workflow-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "mwaa-serverless", "s3"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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


_TRUST_SERVICE = "airflow-serverless.amazonaws.com"


def _simple_dag_yaml(dag_id, bash_command):
    return (
        f"{dag_id}:\n"
        f'  start_date: "2024-01-01"\n'
        f"  schedule: null\n"
        f"  tasks:\n"
        f"    only_task:\n"
        f"      operator: airflow.providers.standard.operators.bash.BashOperator\n"
        f'      bash_command: "{bash_command}"\n'
    )


def _create_dag_bucket(ctx, suffix):
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-mwaascfn-{suffix}-").lower().replace("_", "-")[:63].rstrip("-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        objs = [{"Key": o["Key"]} for o in s3.list_objects_v2(Bucket=name).get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)

    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": name}]})
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    return name


def _put_dag(ctx, bucket, key, yaml_text):
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=yaml_text.encode("utf-8"))


_EXECUTION_POLICY = "sim2real-mwaascfn-access"


def _create_execution_role(ctx, suffix, bucket, key):
    """A tagged role mwaa-serverless assumes: read the one DAG object, write its own task logs."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-mwaascfn-{suffix}-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": _TRUST_SERVICE}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
                           Tags=[{"Key": "sim2real", "Value": role_name}])["Role"]

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=_EXECUTION_POLICY)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)

    partition = role["Arn"].split(":")[1]
    log_groups = (f"arn:{partition}:logs:{ctx.region}:{ctx.account}"
                  ":log-group:/aws/mwaa-serverless/*")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject",
             "Resource": f"arn:{partition}:s3:::{bucket}/{key}"},
            {"Effect": "Allow", "Action": "s3:ListBucket",
             "Resource": f"arn:{partition}:s3:::{bucket}"},
            {"Effect": "Allow",
             "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
                        "logs:DescribeLogStreams", "logs:GetLogEvents"],
             "Resource": [log_groups, f"{log_groups}:log-stream:*"]},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=_EXECUTION_POLICY,
                        PolicyDocument=json.dumps(policy))
    return role["Arn"]


_NOT_FOUND = ("ResourceNotFoundException", "Resource not found")


def _template(name, bucket, key, role_arn, description, resource_tag_value):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Workflow": {
                "Type": "AWS::MWAAServerless::Workflow",
                "Properties": {
                    "Name": name,
                    "Description": description,
                    "DefinitionS3Location": {"Bucket": bucket, "ObjectKey": key},
                    "RoleArn": role_arn,
                    "Tags": {"sim2real-workflow": resource_tag_value},
                },
            },
        },
        "Outputs": {
            "WorkflowRef": {"Value": {"Ref": "Workflow"}},
            "WorkflowVersionAtt": {"Value": {"Fn::GetAtt": ["Workflow", "WorkflowVersion"]}},
            "WorkflowStatusAtt": {"Value": {"Fn::GetAtt": ["Workflow", "WorkflowStatus"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::MWAAServerless::Workflow reads back through mwaa-serverless with its
    templated properties, Ref and GetAtt matching; deleting the stack removes the workflow.
    """
    cf = ctx.client("cloudformation")
    mwaa = ctx.client("mwaa-serverless")

    bucket = _create_dag_bucket(ctx, "rt")
    key = "dags/sim2real.yaml"
    _put_dag(ctx, bucket, key, _simple_dag_yaml("sim2real_dag", "echo hello"))
    role_arn = _create_execution_role(ctx, "rt", bucket, key)

    stack = ctx.unique_name("sim2real-mwaascfn-rt-")
    name = ctx.unique_name("sim2real-mwaascfn-rt-wf-")
    description = "sim2real cloudformation provisioning check"

    stack_id = create_stack(
        ctx, cf, stack, _template(name, bucket, key, role_arn, description, name)
    )
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"
    out = stack_outputs(cf, stack_id)

    # Ref against an independent read (ListWorkflows, paginated), never a read keyed by the Ref.
    workflows = paginate(mwaa, "list_workflows", "Workflows")
    matches = [w for w in workflows if w["Name"] == name]
    assert len(matches) == 1, f"ListWorkflows found {len(matches)} workflow(s) named {name!r}"
    assert matches[0]["WorkflowArn"] == out["WorkflowRef"], (
        f"ListWorkflows WorkflowArn {matches[0]['WorkflowArn']!r} != Ref {out['WorkflowRef']!r}"
    )

    got = mwaa.get_workflow(WorkflowArn=out["WorkflowRef"])
    # Read-only GetAtt == the service value.
    assert got["WorkflowVersion"] == out["WorkflowVersionAtt"], (
        f"GetAtt WorkflowVersion {out['WorkflowVersionAtt']!r} != {got['WorkflowVersion']!r}"
    )
    assert got["WorkflowStatus"] == out["WorkflowStatusAtt"] == "READY", (
        f"GetAtt WorkflowStatus {out['WorkflowStatusAtt']!r}, GetWorkflow {got['WorkflowStatus']!r}"
    )
    # Every templated property, read back through mwaa-serverless.
    assert got["Name"] == name, f"Name {got['Name']!r} != {name!r}"
    assert got["Description"] == description, f"Description {got['Description']!r} != {description!r}"
    assert got["RoleArn"] == role_arn, f"RoleArn {got['RoleArn']!r} != {role_arn!r}"
    assert got["DefinitionS3Location"] == {"Bucket": bucket, "ObjectKey": key}, (
        f"DefinitionS3Location {got['DefinitionS3Location']!r} != bucket/key"
    )

    tags_got = mwaa.list_tags_for_resource(ResourceArn=out["WorkflowRef"])["Tags"]
    tags_got = {k: v for k, v in tags_got.items() if not k.startswith("aws:")}
    assert tags_got == {"sim2real": stack, "sim2real-workflow": name}, f"tags {tags_got!r}"

    delete_stack(cf, stack_id)
    until_raises(lambda: mwaa.get_workflow(WorkflowArn=out["WorkflowRef"]))
    expect_error(lambda: mwaa.get_workflow(WorkflowArn=out["WorkflowRef"]), *_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
