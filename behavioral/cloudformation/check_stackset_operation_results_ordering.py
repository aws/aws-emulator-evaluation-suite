"""stackset-operation-results-ordering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stackset-operation-results-ordering"
GROUP = "ordering"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """ListStackSetOperationResults returns per-region results, stable across calls and matching the target set."""
    cfn = ctx.client("cloudformation")

    # Two distinct regions on purpose -- this check exercises per-region result ordering across
    # a real cross-region StackSet deployment, not a region-restricted resource. Either literal
    # is discarded once it collides with ctx.region.
    region_a = ctx.region
    region_b = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    target_regions = [region_a, region_b]

    stackset_name, admin_role_arn, exec_role_name, account_id = _bootstrap_self_managed_stackset(
        ctx, json.dumps({"Resources": {"Queue": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": 30}}}})
    )

    op_id = _create_instances_until_succeeded(ctx, cfn, stackset_name, account_id, target_regions)

    # UpdateStackSet on a SELF_MANAGED StackSet needs the administration role ARN and exec
    # role name again; without them it is rejected with a ValidationError even though
    # CreateStackSet already associated them.
    update_op_id = cfn.update_stack_set(
        StackSetName=stackset_name,
        TemplateBody=json.dumps({"Resources": {"Queue": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": 60}}}}),
        AdministrationRoleARN=admin_role_arn,
        ExecutionRoleName=exec_role_name,
        OperationPreferences={"FailureTolerancePercentage": 0},
    )["OperationId"]
    update_status = _wait_stackset_op(cfn, stackset_name, update_op_id, timeout_s=300.0)
    assert update_status == "SUCCEEDED", f"UpdateStackSet operation ended as {update_status}"

    results_1 = _list_all_results(cfn, stackset_name, update_op_id)
    results_2 = _list_all_results(cfn, stackset_name, update_op_id)
    assert len(results_1) == len(target_regions), f"expected {len(target_regions)} results, got {results_1}"
    assert results_1 == results_2, "ListStackSetOperationResults order changed across repeated calls"

    got_regions = {r["Region"] for r in results_1}
    assert got_regions == set(target_regions), f"expected regions {target_regions}, got {got_regions}"
    for r in results_1:
        assert r["Account"] == account_id, f"expected account {account_id}, got {r}"
        assert r["Status"] == "SUCCEEDED", r


def _list_all_results(cfn, stackset_name: str, operation_id: str) -> list:
    results: list = []
    kwargs = {"StackSetName": stackset_name, "OperationId": operation_id}
    while True:
        resp = cfn.list_stack_set_operation_results(**kwargs)
        results.extend(resp.get("Summaries", []))
        token = resp.get("NextToken")
        if not token:
            return results
        kwargs["NextToken"] = token


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
        admin_role = iam.create_role(RoleName=admin_role_name, AssumeRolePolicyDocument=json.dumps(admin_trust))["Role"]
        ctx.on_cleanup(lambda: _delete_role(ctx, admin_role_name))

        exec_trust = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_role["Arn"]}, "Action": "sts:AssumeRole"}],
        }
        # Referencing the admin role's ARN (just created, moments ago, in this same run) as a
        # Principal is itself eventually consistent on IAM's side: CreateRole can transiently
        # reject it with MalformedPolicyDocument ("Invalid principal in policy") until the admin
        # role propagates. Retry that specific error rather than failing the whole bootstrap.
        exec_role = _retry_malformed_principal(
            lambda: iam.create_role(RoleName=exec_role_name, AssumeRolePolicyDocument=json.dumps(exec_trust))["Role"]
        )
        ctx.on_cleanup(lambda: _delete_role(ctx, exec_role_name))
        iam.attach_role_policy(RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSQSFullAccess")
        # CloudFormation operates the deployed stack as the assumed execution role, so the
        # exec role needs CloudFormation stack permissions besides the SQS ones (otherwise
        # "not authorized to perform: cloudformation:CreateStack").
        iam.put_role_policy(
            RoleName=exec_role_name,
            PolicyName="StackSetExecuteStacks",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                        "cloudformation:CreateStack",
                        "cloudformation:UpdateStack",
                        "cloudformation:DeleteStack",
                        "cloudformation:DescribeStacks",
                        "cloudformation:DescribeStackEvents",
                        "cloudformation:GetTemplate",
                    ],
                    "Resource": "*",
                }],
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


def _retry_malformed_principal(fn, attempts: int = 8, delay_s: float = 5.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            if exc.response.get("Error", {}).get("Code") != "MalformedPolicyDocument":
                raise
            time.sleep(delay_s)
    raise last_exc


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


def _create_instances_until_succeeded(
    ctx, cfn, stackset_name: str, account_id: str, regions: list, timeout_s: float = 240.0
) -> str:
    """Create cross-region stack instances, retrying the whole create+await cycle while (and
    only while) the failure is StackSets' own IAM trust-relationship visibility check lagging
    role creation, which can trail put_role_policy by several seconds. A
    FailureTolerancePercentage of 0 means a failed attempt creates no stack instances in any
    region, so retrying the full call is safe: there is nothing to reconcile from the failed try.
    """
    deadline = time.monotonic() + timeout_s
    last_reasons: list = []
    while time.monotonic() < deadline:
        try:
            op_id = cfn.create_stack_instances(
                StackSetName=stackset_name, Accounts=[account_id], Regions=regions
            )["OperationId"]
        except ClientError as exc:
            last_reasons = [str(exc)]
            time.sleep(5)
            continue

        remaining = max(30.0, deadline - time.monotonic())
        status = _wait_stackset_op(cfn, stackset_name, op_id, timeout_s=remaining)
        if status == "SUCCEEDED":
            ctx.on_cleanup(
                lambda: cfn.delete_stack_instances(
                    StackSetName=stackset_name, Accounts=[account_id], Regions=regions, RetainStacks=False
                )
            )
            return op_id

        last_reasons = [r.get("StatusReason", "") for r in _list_all_results(cfn, stackset_name, op_id)]
        if not any("trust relationship" in (reason or "") for reason in last_reasons):
            raise AssertionError(f"CreateStackInstances ended as {status} for a non-propagation reason: {last_reasons}")
        time.sleep(2)
    raise AssertionError(f"unreachable: CreateStackInstances never succeeded within {timeout_s}s (role propagation?): {last_reasons}")


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
