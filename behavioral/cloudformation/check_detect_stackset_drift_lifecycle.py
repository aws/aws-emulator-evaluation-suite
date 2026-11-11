"""detect-stackset-drift-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "detect-stackset-drift-lifecycle"
GROUP = "server-side"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DetectStackSetDrift runs a stack-set operation and produces an aggregated drift status."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    stackset_name, admin_role_arn, exec_role_name, account_id = _bootstrap_self_managed_stackset(
        ctx, json.dumps({"Resources": {"Queue": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": 30}}}})
    )

    _create_instances_with_retry(ctx, cfn, stackset_name, account_id, ctx.region)

    instance = cfn.describe_stack_instance(
        StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
    )["StackInstance"]
    instance_stack_id = instance["StackId"]
    queue_url = cfn.describe_stack_resource(StackName=instance_stack_id, LogicalResourceId="Queue")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]

    # cause real, out-of-band drift on the instance's queue
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"VisibilityTimeout": "111"})

    drift_op_id = cfn.detect_stack_set_drift(StackSetName=stackset_name)["OperationId"]
    final_status = _wait_stackset_op(cfn, stackset_name, drift_op_id, timeout_s=300.0)
    assert final_status == "SUCCEEDED", f"drift-detection operation ended as {final_status}"

    details = cfn.describe_stack_set(StackSetName=stackset_name)["StackSet"]["StackSetDriftDetectionDetails"]
    assert details["DriftStatus"] == "DRIFTED", f"expected DRIFTED stack set drift status, got {details}"
    drifted_count = details.get("DriftedStackInstancesCount", 0)
    assert drifted_count >= 1, f"expected at least 1 drifted stack instance, got {drifted_count} (details={details})"


# ===== helpers =====

def _bootstrap_self_managed_stackset(ctx, template_body: str):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    cfn = ctx.client("cloudformation")
    account_id = sts.get_caller_identity()["Account"]

    admin_role_name = ctx.unique_name("sim2real-cfnadmin-")
    exec_role_name = ctx.unique_name("sim2real-cfnexec-")

    tag = [{"Key": "sim2real-behav", "Value": CHECK}]
    try:
        admin_trust = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
        admin_role = iam.create_role(
            RoleName=admin_role_name, AssumeRolePolicyDocument=json.dumps(admin_trust), Tags=tag
        )["Role"]
        ctx.on_cleanup(lambda: _delete_role(ctx, admin_role_name))

        exec_trust = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_role["Arn"]}, "Action": "sts:AssumeRole"}],
        }
        exec_role = _create_role_with_retry(iam, exec_role_name, exec_trust, tag)["Role"]
        ctx.on_cleanup(lambda: _delete_role(ctx, exec_role_name))
        # the execution role must itself run CloudFormation's stack operations (CreateStack et
        # al.), not just manage the template's resources, so it needs more than SQS access.
        iam.attach_role_policy(RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        iam.put_role_policy(
            RoleName=admin_role_name,
            PolicyName="AssumeExecRole",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": exec_role["Arn"]}],
            }),
        )
    except ClientError as exc:
        raise AssertionError(f"unreachable: cannot provision self-managed StackSet IAM roles: {exc}")

    stackset_name = ctx.unique_name("sim2real-stackset-")
    created = False
    last_err = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        try:
            cfn.create_stack_set(
                StackSetName=stackset_name,
                TemplateBody=template_body,
                PermissionModel="SELF_MANAGED",
                AdministrationRoleARN=admin_role["Arn"],
                ExecutionRoleName=exec_role_name,
                Tags=tag,
            )
            created = True
            break
        except ClientError as exc:
            last_err = exc
            time.sleep(5)
    if not created:
        raise AssertionError(f"unreachable: CreateStackSet never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: _delete_stack_set(cfn, stackset_name))

    return stackset_name, admin_role["Arn"], exec_role_name, account_id


def _create_role_with_retry(iam, role_name: str, trust_policy: dict, tags: list, timeout_s: float = 60.0, interval_s: float = 5.0):
    """IAM principals referenced in a fresh role's trust policy can lag briefly behind
    creation; retry MalformedPolicyDocument to absorb that propagation delay."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=tags)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_stack_set(cfn, stackset_name: str, timeout_s: float = 600.0) -> None:
    """DeleteStackSet is refused with OperationInProgressException while the stack-instance
    deletion runs; retry that refusal every 2 s to a deadline. A missing stack set is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cfn.delete_stack_set(StackSetName=stackset_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "StackSetNotFoundException":
                return
            if code != "OperationInProgressException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        for pol_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol_name)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_instances_with_retry(ctx, cfn, stackset_name: str, account_id: str, region: str, timeout_s: float = 180.0) -> None:
    """CreateStackInstances has CloudFormation assume the just-created execution role via
    the admin role; that assume-role trust can still lag IAM's propagation delay even after
    both roles exist, and it surfaces as a FAILED async operation, not a synchronous error.
    Retry the whole operation, not just the API call."""
    ctx.on_cleanup(
        lambda: cfn.delete_stack_instances(
            StackSetName=stackset_name, Accounts=[account_id], Regions=[region], RetainStacks=False
        )
    )
    deadline = time.monotonic() + timeout_s
    status = None
    detail = None
    while time.monotonic() < deadline:
        try:
            op_id = cfn.create_stack_instances(
                StackSetName=stackset_name, Accounts=[account_id], Regions=[region]
            )["OperationId"]
        except ClientError as exc:
            status, detail = None, str(exc)
            time.sleep(5)
            continue
        status = _wait_stackset_op(cfn, stackset_name, op_id)
        if status == "SUCCEEDED":
            return
        detail = cfn.describe_stack_instance(
            StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=region
        )["StackInstance"].get("StatusReason")
        time.sleep(2)
    raise AssertionError(f"unreachable: CreateStackInstances never succeeded (role propagation?): status={status} detail={detail}")


def _wait_stackset_op(cfn, stackset_name: str, operation_id: str, timeout_s: float = 240.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stack_set_operation(StackSetName=stackset_name, OperationId=operation_id)[
            "StackSetOperation"
        ]["Status"]
        if status in ("SUCCEEDED", "FAILED", "STOPPED"):
            return status
        time.sleep(4)
    raise AssertionError(f"stack set operation {operation_id} did not finish within {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
