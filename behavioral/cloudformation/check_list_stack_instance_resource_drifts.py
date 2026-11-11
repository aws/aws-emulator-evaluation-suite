"""list-stack-instance-resource-drifts."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-stack-instance-resource-drifts"
GROUP = "server-side"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListStackInstanceResourceDrifts surfaces per-instance drift results tied to a drift-detection OperationId."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    stackset_name, admin_role_arn, exec_role_name, account_id = _bootstrap_self_managed_stackset(
        ctx, json.dumps({"Resources": {"Queue": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": 30}}}})
    )

    op_id = _create_instances_with_retry(ctx, cfn, stackset_name, account_id, ctx.region)

    instance = cfn.describe_stack_instance(
        StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
    )["StackInstance"]
    queue_url = cfn.describe_stack_resource(StackName=instance["StackId"], LogicalResourceId="Queue")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"VisibilityTimeout": "222"})

    drift_op_id = cfn.detect_stack_set_drift(StackSetName=stackset_name)["OperationId"]
    final_status = _wait_stackset_op(cfn, stackset_name, drift_op_id, timeout_s=200.0)
    assert final_status == "SUCCEEDED", (
        f"drift-detection operation ended as {final_status}: "
        f"{cfn.list_stack_set_operation_results(StackSetName=stackset_name, OperationId=drift_op_id)['Summaries']}"
    )

    summaries = cfn.list_stack_instance_resource_drifts(
        StackSetName=stackset_name,
        StackInstanceAccount=account_id,
        StackInstanceRegion=ctx.region,
        OperationId=drift_op_id,
    )["Summaries"]
    assert summaries, "expected at least one per-resource drift summary for the instance"
    by_logical_id = {s["LogicalResourceId"]: s for s in summaries}
    assert "Queue" in by_logical_id, by_logical_id
    assert by_logical_id["Queue"]["StackResourceDriftStatus"] == "MODIFIED", by_logical_id["Queue"]

    # a bogus/unrelated OperationId must be rejected, not silently return the same summaries
    code, message = _error(
        lambda: cfn.list_stack_instance_resource_drifts(
            StackSetName=stackset_name,
            StackInstanceAccount=account_id,
            StackInstanceRegion=ctx.region,
            OperationId=ctx.unique_name("bogus-op-"),
        )
    )
    assert code == "OperationNotFoundException", f"expected OperationNotFoundException, got {code}"
    assert message == "Detect Drift Operation not found", (
        f"unexpected OperationNotFoundException message {message!r}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _bootstrap_self_managed_stackset(ctx, template_body: str):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    cfn = ctx.client("cloudformation")
    account_id = sts.get_caller_identity()["Account"]

    admin_role_name = ctx.unique_name("sim2real-cfnadmin-")
    exec_role_name = ctx.unique_name("sim2real-cfnexec-")

    try:
        admin_trust = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
        admin_role = iam.create_role(
            RoleName=admin_role_name,
            AssumeRolePolicyDocument=json.dumps(admin_trust),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["Role"]
        ctx.on_cleanup(lambda: _delete_role(ctx, admin_role_name))

        exec_trust = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_role["Arn"]}, "Action": "sts:AssumeRole"}],
        }
        # the admin role's ARN is eventually consistent as a trust-policy principal: IAM's policy
        # validator can reject it as "Invalid principal" for a few seconds after CreateRole returns.
        exec_role = None
        principal_deadline = time.monotonic() + 30.0
        last_principal_err = None
        while time.monotonic() < principal_deadline:
            try:
                exec_role = iam.create_role(
                    RoleName=exec_role_name,
                    AssumeRolePolicyDocument=json.dumps(exec_trust),
                    Tags=[{"Key": "sim2real", "Value": CHECK}],
                )["Role"]
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "MalformedPolicyDocument":
                    raise
                last_principal_err = exc
                time.sleep(3)
        if exec_role is None:
            raise AssertionError(
                f"unreachable: CreateRole never accepted admin role {admin_role['Arn']!r} as a trust "
                f"principal (IAM principal propagation?): {last_principal_err}"
            )
        ctx.on_cleanup(lambda: _delete_role(ctx, exec_role_name))
        iam.attach_role_policy(RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSQSFullAccess")
        # a self-managed StackSet's execution role must itself be allowed to operate the stacks
        # CloudFormation drives on its behalf; AmazonSQSFullAccess only covers the deployed resource.
        # Several stack-set operations (e.g. DescribeStackDriftDetectionStatus, keyed by a detection
        # id rather than a stack name) do not support resource-level permissions, so this throwaway,
        # check-scoped role is granted on Resource "*" rather than a stack ARN pattern.
        iam.put_role_policy(
            RoleName=exec_role_name,
            PolicyName="StackSetExecution",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "cloudformation:*", "Resource": "*"}],
            }),
        )
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
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            created = True
            break
        except ClientError as exc:
            last_err = exc
            time.sleep(5)
    if not created:
        raise AssertionError(f"unreachable: CreateStackSet never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=stackset_name))

    return stackset_name, admin_role["Arn"], exec_role_name, account_id


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


def _create_instances_with_retry(ctx, cfn, stackset_name: str, account_id: str, region: str, timeout_s: float = 200.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_detail = None
    while time.monotonic() < deadline:
        try:
            op_id = cfn.create_stack_instances(
                StackSetName=stackset_name, Accounts=[account_id], Regions=[region]
            )["OperationId"]
        except ClientError as exc:
            last_detail = exc
            time.sleep(5)
            continue

        status = _wait_stackset_op(cfn, stackset_name, op_id, timeout_s=max(30.0, deadline - time.monotonic()))
        if status == "SUCCEEDED":
            ctx.on_cleanup(lambda: _delete_instances_and_wait(cfn, stackset_name, account_id, region))
            return op_id

        # the exec role's trust relationship to the admin role is eventually consistent: CFN's own
        # account gate can still reject a role CreateRole already reported as created. Clear the
        # FAILED instance record and retry rather than treating this as a hard failure.
        last_detail = cfn.list_stack_set_operation_results(StackSetName=stackset_name, OperationId=op_id)["Summaries"]
        try:
            delete_op_id = cfn.delete_stack_instances(
                StackSetName=stackset_name, Accounts=[account_id], Regions=[region], RetainStacks=False
            )["OperationId"]
            _wait_stackset_op(cfn, stackset_name, delete_op_id, timeout_s=60.0)
        except ClientError:
            pass
        time.sleep(2)
    raise AssertionError(f"unreachable: CreateStackInstances never succeeded (role propagation?): {last_detail}")


def _delete_instances_and_wait(cfn, stackset_name: str, account_id: str, region: str) -> None:
    """Teardown: DeleteStackSet refuses while the instance deletion is still running, so wait it out."""
    delete_op_id = cfn.delete_stack_instances(
        StackSetName=stackset_name, Accounts=[account_id], Regions=[region], RetainStacks=False
    )["OperationId"]
    status = _wait_stackset_op(cfn, stackset_name, delete_op_id, timeout_s=300.0)
    if status != "SUCCEEDED":
        raise AssertionError(f"stack instance deletion {delete_op_id} ended as {status}")


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
