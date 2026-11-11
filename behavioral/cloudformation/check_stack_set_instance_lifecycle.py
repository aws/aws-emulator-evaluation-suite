"""stack-set-instance-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-set-instance-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack set instance transitions CURRENT->CREATE_IN_PROGRESS->CURRENT and is
    removed on delete, reflected consistently across describe/list."""
    cfn = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    admin_arn, exec_role_name = _ensure_stackset_roles(ctx)

    ss_name = ctx.unique_name("sim2real-ssinst-")
    template = json.dumps(
        {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}}
    )
    cfn.create_stack_set(
        StackSetName=ss_name,
        TemplateBody=template,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_role_name,
    )

    def _cleanup():
        try:
            cfn.delete_stack_instances(
                StackSetName=ss_name, Accounts=[account], Regions=[region], RetainStacks=False
            )
            _poll_until(
                lambda: _error_code(lambda: cfn.describe_stack_instance(
                    StackSetName=ss_name, StackInstanceAccount=account, StackInstanceRegion=region
                )),
                lambda code: code == "StackInstanceNotFoundException",
                timeout_s=300,
                interval_s=10,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "OperationNotFoundException",
                "StackInstanceNotFoundException",
                "StackSetNotFoundException",
            ):
                raise
        try:
            cfn.delete_stack_set(StackSetName=ss_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StackSetNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    create_result = _create_stack_instances_past_role_propagation(cfn, ss_name, account, region)
    assert create_result["Status"] == "SUCCEEDED", (
        f"create_stack_instances operation ended as {create_result['Status']}: "
        f"{create_result.get('StatusReason')!r}"
    )

    instance = cfn.describe_stack_instance(
        StackSetName=ss_name, StackInstanceAccount=account, StackInstanceRegion=region
    )["StackInstance"]
    assert instance["Status"] == "CURRENT", instance

    listed = cfn.list_stack_instances(StackSetName=ss_name)["Summaries"]
    assert any(s["Account"] == account and s["Region"] == region for s in listed), listed

    delete_op = cfn.delete_stack_instances(
        StackSetName=ss_name, Accounts=[account], Regions=[region], RetainStacks=False
    )["OperationId"]

    def _delete_op_status():
        return cfn.describe_stack_set_operation(StackSetName=ss_name, OperationId=delete_op)[
            "StackSetOperation"
        ]["Status"]

    d_status = _poll_until(
        _delete_op_status, lambda s: s in ("SUCCEEDED", "FAILED", "STOPPED"), timeout_s=420, interval_s=10
    )
    assert d_status == "SUCCEEDED", f"delete_stack_instances operation ended as {d_status}"

    final_code = _poll_until(
        lambda: _error_code(
            lambda: cfn.describe_stack_instance(
                StackSetName=ss_name, StackInstanceAccount=account, StackInstanceRegion=region
            )
        ),
        lambda code: code == "StackInstanceNotFoundException",
        timeout_s=120,
        interval_s=5,
    )
    assert final_code == "StackInstanceNotFoundException"

    final_listed = cfn.list_stack_instances(StackSetName=ss_name)["Summaries"]
    assert not any(s["Account"] == account and s["Region"] == region for s in final_listed)

    # the dead instance is unusable, not just absent from reads: a mutation targeting it
    # must fail (synchronously or via its operation's terminal status), never resurrect it
    try:
        mutate_op = cfn.update_stack_instances(
            StackSetName=ss_name, Accounts=[account], Regions=[region], ParameterOverrides=[]
        )["OperationId"]
    except ClientError as exc:
        mutate_code = exc.response.get("Error", {}).get("Code")
        assert mutate_code == "StackInstanceNotFoundException", (
            f"UpdateStackInstances on a deleted instance should reject not-found, got {mutate_code}"
        )
        mutate_msg = exc.response.get("Error", {}).get("Message")
        assert mutate_msg == f"No Stack Instance found in region {region}", mutate_msg
    else:
        mutate_status = _poll_until(
            lambda: cfn.describe_stack_set_operation(StackSetName=ss_name, OperationId=mutate_op)[
                "StackSetOperation"
            ]["Status"],
            lambda s: s in ("SUCCEEDED", "FAILED", "STOPPED"),
            timeout_s=180,
            interval_s=5,
        )
        assert mutate_status != "SUCCEEDED", (
            f"UpdateStackInstances on a deleted instance must not succeed, got {mutate_status}"
        )

    post_mutate_listed = cfn.list_stack_instances(StackSetName=ss_name)["Summaries"]
    assert not any(s["Account"] == account and s["Region"] == region for s in post_mutate_listed), (
        "a rejected UpdateStackInstances on a deleted instance must not have resurrected it"
    )


_SUCCEEDED = "<call succeeded>"


def _error_code(fn):
    """Return the Error.Code of the ClientError fn() raises, or _SUCCEEDED (which no
    error code equals) when the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return _SUCCEEDED


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


def _retry_role_propagation(fn, attempts: int = 10, delay_s: float = 5.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("AccessDenied", "ValidationError", "InvalidOperationException"):
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _retry_malformed_principal(fn, attempts: int = 10, delay_s: float = 5.0):
    # IAM's cross-role principal validation on CreateRole is itself eventually
    # consistent: referencing a role ARN created moments ago as a trust-policy
    # Principal can transiently 400 with MalformedPolicyDocumentException until
    # that propagates.
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "MalformedPolicyDocument":
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _create_stack_instances_past_role_propagation(cfn, ss_name, account, region, attempts=5, delay_s=20.0):
    # IAM role propagation can lag past the point where CreateRole itself succeeds and
    # AssumeStackSetExecRole/AdministratorAccess are attached: StackSets' own attempt to
    # assume the freshly-created roles can still fail the whole async CreateStackInstances
    # operation (Status=FAILED) even though the API call that started it returned 200.
    # Retrying the operation itself (not just the initial call) rides out that window.
    result = None
    for _ in range(attempts):
        create_op = _retry_role_propagation(
            lambda: cfn.create_stack_instances(StackSetName=ss_name, Accounts=[account], Regions=[region])[
                "OperationId"
            ]
        )
        result = _poll_until(
            lambda: cfn.describe_stack_set_operation(StackSetName=ss_name, OperationId=create_op)[
                "StackSetOperation"
            ],
            lambda o: o["Status"] in ("SUCCEEDED", "FAILED", "STOPPED"),
            timeout_s=420,
            interval_s=10,
        )
        if result["Status"] == "SUCCEEDED":
            return result
        time.sleep(delay_s)
    return result


def _ensure_stackset_roles(ctx):
    """Bootstrap the standard self-managed StackSets admin/execution roles if absent.

    These are conventional, account-wide, fixed-name roles; we never delete them in
    cleanup since concurrent checks may depend on them (mirrors real-world one-time
    account bootstrap for StackSets self-managed permissions).
    """
    iam = ctx.client("iam")
    admin_role_name = "AWSCloudFormationStackSetAdministrationRole"
    exec_role_name = "AWSCloudFormationStackSetExecutionRole"

    admin_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    try:
        admin_role = iam.get_role(RoleName=admin_role_name)["Role"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
        try:
            admin_role = iam.create_role(RoleName=admin_role_name, AssumeRolePolicyDocument=admin_trust)["Role"]
        except ClientError as create_exc:
            # a concurrent check may have created it between our get and our create
            if create_exc.response["Error"]["Code"] != "EntityAlreadyExists":
                raise
            admin_role = iam.get_role(RoleName=admin_role_name)["Role"]
    iam.put_role_policy(
        RoleName=admin_role_name,
        PolicyName="AssumeStackSetExecRole",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::*:role/{exec_role_name}"}
                ],
            }
        ),
    )

    exec_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_role["Arn"]}, "Action": "sts:AssumeRole"}],
        }
    )
    try:
        iam.get_role(RoleName=exec_role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
        try:
            _retry_malformed_principal(
                lambda: iam.create_role(RoleName=exec_role_name, AssumeRolePolicyDocument=exec_trust)
            )
        except ClientError as create_exc:
            if create_exc.response["Error"]["Code"] != "EntityAlreadyExists":
                raise
    iam.attach_role_policy(RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")

    return admin_role["Arn"], exec_role_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
