"""deploy-mwaa-environment-network-configuration-single-subnet-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-mwaa-environment-network-configuration-single-subnet-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "mwaa"]

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

_VPC_CIDR = "10.84.0.0/16"
_PRIVATE_CIDRS = ("10.84.1.0/24", "10.84.2.0/24")
_CHANGE_SET = "sim2real-control"


def _trust_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": ["airflow.amazonaws.com", "airflow-env.amazonaws.com"]},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _execution_policy(env_name: str) -> dict:
    """The execution role policy Amazon MWAA documents, scoped to this environment's resources."""
    bucket = {"Fn::GetAtt": ["Bucket", "Arn"]}
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "airflow:PublishMetrics", "Resource": {"Fn::Sub": (
                "arn:${AWS::Partition}:airflow:${AWS::Region}:${AWS::AccountId}:environment/"
                + env_name)}},
            {"Effect": "Allow", "Action": ["s3:GetObject*", "s3:GetBucket*", "s3:List*"],
             "Resource": [bucket, {"Fn::Sub": ["${Arn}/*", {"Arn": bucket}]}]},
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogStream",
                    "logs:CreateLogGroup",
                    "logs:PutLogEvents",
                    "logs:GetLogEvents",
                    "logs:GetLogRecord",
                    "logs:GetLogGroupFields",
                    "logs:GetQueryResults",
                ],
                "Resource": {"Fn::Sub": (
                    "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:airflow-"
                    + env_name + "-*")},
            },
            {"Effect": "Allow", "Action": ["logs:DescribeLogGroups", "cloudwatch:PutMetricData"],
             "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": [
                    "sqs:ChangeMessageVisibility",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes",
                    "sqs:GetQueueUrl",
                    "sqs:ReceiveMessage",
                    "sqs:SendMessage",
                ],
                "Resource": {"Fn::Sub": "arn:${AWS::Partition}:sqs:${AWS::Region}:*:airflow-celery-*"},
            },
            {
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey*", "kms:Encrypt"],
                "Resource": "*",
                "Condition": {"StringLike": {"kms:ViaService": [
                    {"Fn::Sub": "sqs.${AWS::Region}.amazonaws.com"}]}},
            },
        ],
    }


def _template(env_name: str, subnet_count: int) -> str:
    """The round trip's environment with real VPC, two subnets, security group, bucket and role;
    SubnetIds names the first ``subnet_count`` subnets. No egress path, since the refusal is a
    property validation before MWAA is called."""
    t = [{"Key": "sim2real-env", "Value": env_name}]
    subnet_ids = [{"Ref": f"PrivateSubnet{i + 1}"} for i in range(subnet_count)]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {
                "CidrBlock": _VPC_CIDR, "EnableDnsSupport": True, "EnableDnsHostnames": True,
                "Tags": t,
            }},
            **{f"PrivateSubnet{i + 1}": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": cidr,
                "AvailabilityZone": {"Fn::Select": [i, {"Fn::GetAZs": ""}]}, "Tags": t,
            }} for i, cidr in enumerate(_PRIVATE_CIDRS)},
            "Sg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "GroupDescription": "sim2real mwaa provisioning check",
                "Tags": t,
            }},
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {
                "VersioningConfiguration": {"Status": "Enabled"}, "Tags": t,
            }},
            "ExecutionRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": _trust_policy(),
                "Policies": [{"PolicyName": "exec", "PolicyDocument": _execution_policy(env_name)}],
                "Tags": t,
            }},
            "MwaaEnvironment": {
                "Type": "AWS::MWAA::Environment",
                "Properties": {
                    "Name": env_name,
                    "ExecutionRoleArn": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                    "SourceBucketArn": {"Fn::GetAtt": ["Bucket", "Arn"]},
                    "DagS3Path": "dags",
                    # NetworkConfiguration.SubnetIds requires exactly 2; the rejected stack names 1.
                    "NetworkConfiguration": {
                        "SubnetIds": subnet_ids,
                        "SecurityGroupIds": [{"Ref": "Sg"}],
                    },
                    "EnvironmentClass": "mw1.micro",
                    "MaxWorkers": 1,
                    "MinWorkers": 1,
                    "WebserverAccessMode": "PRIVATE_ONLY",
                    "Tags": {"sim2real-env": env_name},
                },
            },
        },
    })


def _control_change_set(ctx, cfn, env_name):
    """A CREATE change set of the two-subnet template: it passes pre-deployment validation and
    plans the environment, and is never executed: the stack's cleanup deletes it unexecuted."""
    name = ctx.unique_name("sim2real-mwaacfnctl-")
    # Cleanup first, as create_stack does: a stack AWS accepted is deleted even if the call raises.
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cfn, name, created.get("StackId")))
    resp = cfn.create_change_set(
        StackName=name, ChangeSetName=_CHANGE_SET, ChangeSetType="CREATE",
        TemplateBody=_template(env_name, 2), Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": name}],
    )
    stack_id, change_set_id = resp["StackId"], resp["Id"]
    created["StackId"] = stack_id
    deadline = time.monotonic() + 300.0
    while True:
        change_set = cfn.describe_change_set(ChangeSetName=change_set_id)
        if change_set["Status"] in ("CREATE_COMPLETE", "FAILED"):
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"change set {change_set_id} still {change_set['Status']!r}")
        time.sleep(2)
    return stack_id, change_set


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::MWAA::Environment naming one subnet fails property validation with
    the exact minimum-item-count reason, rolls back, and MWAA never holds it; the same template
    naming two subnets passes pre-deployment validation as an unexecuted CREATE change set.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-mwaa-environment.html
    """
    cfn = ctx.client("cloudformation")
    mwaa = ctx.client("mwaa")
    env_name = ctx.unique_name("sim2real-mwaa-env-")
    good_name = ctx.unique_name("sim2real-mwaa-envgood-")

    # Positive control: SubnetIds given a VALID two-subnet value, planned but never executed.
    good_id, change_set = _control_change_set(ctx, cfn, good_name)
    assert change_set["Status"] == "CREATE_COMPLETE", (
        f"control change set ended {change_set['Status']!r}: {change_set.get('StatusReason')!r}"
    )
    planned = [(c["ResourceChange"]["Action"], c["ResourceChange"]["ResourceType"])
               for c in change_set["Changes"]
               if c["ResourceChange"]["LogicalResourceId"] == "MwaaEnvironment"]
    assert planned == [("Add", "AWS::MWAA::Environment")], f"control plans {planned!r}"
    rows = validation_rows(cfn, good_id)
    assert rows == [], f"control change set has validation errors: {rows!r}"

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-mwaacfnbad-"),
                            _template(env_name, 1), Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "ROLLBACK_COMPLETE", f"stack ended {status!r}, expected ROLLBACK_COMPLETE"

    reason = failed_reason(stack_events(cfn, stack_id), "MwaaEnvironment")
    want_reason = (
        "Properties validation failed for resource MwaaEnvironment with message:\n"
        "#/NetworkConfiguration/SubnetIds: expected minimum item count: 2, found: 1"
    )
    assert reason == want_reason, f"reason {reason!r}, expected {want_reason!r}"

    # Rollback absence through Amazon MWAA, by the declared name, before this check deletes.
    listed = [n for n in paginate(mwaa, "list_environments", "Environments") if n == env_name]
    assert listed == [], f"the rolled-back environment is listed: {listed!r}"
    not_found = ("ResourceNotFoundException", f"Environment {env_name} not found.")
    expect_error(lambda: mwaa.get_environment(Name=env_name), *not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
