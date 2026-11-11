"""deploy-mwaaserverless-workflow-invalid-rolearn-pattern-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-mwaaserverless-workflow-invalid-rolearn-pattern-rejected"
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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----


_TRUST_SERVICE = "airflow-serverless.amazonaws.com"
_BAD_ROLE_ARN = "not-a-valid-role-arn"
_VALIDATION_REASON = (
    f"Property value [{_BAD_ROLE_ARN}] does not match pattern: "
    r"^arn:aws(?:-(?:cn|us-gov|iso|iso-b|iso-e|iso-f))?:iam::[0-9]{12}:role"
    r"(/[a-zA-Z0-9+=,.@_-]{1,512})*?/[a-zA-Z0-9+=,.@_-]{1,64}$"
)


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
    name = ctx.unique_name(f"sim2real-mwaascfnneg-{suffix}-").lower().replace("_", "-")[:63].rstrip("-")
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
    role_name = ctx.unique_name(f"sim2real-mwaascfnneg-{suffix}-")
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


def _template(name, bucket, key, role_arn):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Workflow": {
                "Type": "AWS::MWAAServerless::Workflow",
                "Properties": {
                    "Name": name,
                    "DefinitionS3Location": {"Bucket": bucket, "ObjectKey": key},
                    "RoleArn": role_arn,
                },
            },
        },
        "Outputs": {"WorkflowRef": {"Value": {"Ref": "Workflow"}}},
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::MWAAServerless::Workflow with a RoleArn that fails the type's ARN
    pattern is refused by early validation and never creates a workflow, while the same template
    with a well-formed RoleArn deploys.
    """
    cf = ctx.client("cloudformation")
    mwaa = ctx.client("mwaa-serverless")

    bucket = _create_dag_bucket(ctx, "neg")
    key = "dags/sim2real.yaml"
    _put_dag(ctx, bucket, key, _simple_dag_yaml("sim2real_dag", "echo hello"))
    role_arn = _create_execution_role(ctx, "neg", bucket, key)

    # Positive control: the SAME template, RoleArn given a VALID value (never dropped).
    good_name = ctx.unique_name("sim2real-mwaascfnneg-good-wf-")
    good_stack = ctx.unique_name("sim2real-mwaascfnneg-good-")
    good_id = create_stack(ctx, cf, good_stack, _template(good_name, bucket, key, role_arn))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cf, good_id))!r}"
    )
    ref = stack_outputs(cf, good_id)["WorkflowRef"]
    listed = [w for w in paginate(mwaa, "list_workflows", "Workflows") if w["Name"] == good_name]
    assert [w["WorkflowArn"] for w in listed] == [ref], (
        f"ListWorkflows entries named {good_name!r}: {listed!r}, Ref {ref!r}"
    )
    got = mwaa.get_workflow(WorkflowArn=listed[0]["WorkflowArn"])
    read = (got["RoleArn"], got["DefinitionS3Location"])
    want = (role_arn, {"Bucket": bucket, "ObjectKey": key})
    assert read == want, f"control workflow reads (RoleArn, DefinitionS3Location) {read!r}"

    # The bad stack: only RoleArn changed to a value that fails the resource schema's pattern.
    bad_name = ctx.unique_name("sim2real-mwaascfnneg-bad-wf-")
    bad_stack = ctx.unique_name("sim2real-mwaascfnneg-bad-")
    bad_id = create_stack(ctx, cf, bad_stack, _template(bad_name, bucket, key, _BAD_ROLE_ARN))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"

    rows = validation_rows(cf, bad_id)
    assert rows == [
        ("Workflow", "PROPERTY_VALIDATION", "FAILED", "FAIL", _VALIDATION_REASON,
         "/Resources/Workflow/Properties/RoleArn"),
    ], f"validation rows {rows!r}"

    # Rollback absence through mwaa-serverless, by the name the workflow would have, before delete.
    workflows = paginate(mwaa, "list_workflows", "Workflows")
    matches = [w for w in workflows if w["Name"] == bad_name]
    assert matches == [], f"the rejected workflow is listed: {matches!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
