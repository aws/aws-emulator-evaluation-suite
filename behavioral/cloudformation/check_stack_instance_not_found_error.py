"""stack-instance-not-found-error."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-instance-not-found-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps(
    {
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {}},
        }
    }
)

# Any real AWS region other than ctx.region works as the "never targeted" key for
# the negative leg below; this one isn't special, just enabled by default.
_UNDEPLOYED_REGION = "us-east-2"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStackInstance for an account/region combination with no deployed instance
    returns StackInstanceNotFoundException, even though the StackSet itself exists — and,
    as a positive control, the identical call succeeds for a region that DOES have one."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    negative_region = _UNDEPLOYED_REGION if ctx.region != _UNDEPLOYED_REGION else "eu-west-1"

    admin_arn, exec_role_name = _ensure_stackset_roles(ctx)

    stackset_name = ctx.unique_name("sim2real-behav-ss-")
    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=_TEMPLATE,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_role_name,
    )

    def _cleanup():
        try:
            cfn.delete_stack_instances(
                StackSetName=stackset_name,
                Accounts=[account_id],
                Regions=[ctx.region],
                RetainStacks=False,
            )
            _poll_until(
                lambda: _instance_absent(cfn, stackset_name, account_id, ctx.region),
                lambda absent: absent,
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
            cfn.delete_stack_set(StackSetName=stackset_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StackSetNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # Positive control: deploy a real instance into ctx.region and prove
    # DescribeStackInstance succeeds for it first — otherwise a target that rejects
    # every DescribeStackInstance call would pass this check for the wrong reason.
    status, reason = _create_stack_instance_retrying(cfn, stackset_name, account_id, ctx.region)
    assert status == "SUCCEEDED", f"create_stack_instances operation ended as {status}: {reason}"

    control = cfn.describe_stack_instance(
        StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
    )["StackInstance"]
    assert control["Status"] == "CURRENT", f"expected positive control CURRENT, got {control}"

    # Negative: this StackSet has never been targeted at negative_region, so describing
    # that account/region combination must fail not-found.
    code, msg = _client_error(
        lambda: cfn.describe_stack_instance(
            StackSetName=stackset_name,
            StackInstanceAccount=account_id,
            StackInstanceRegion=negative_region,
        )
    )
    assert code == "StackInstanceNotFoundException", f"expected StackInstanceNotFoundException, got {code}"
    assert msg == "StackInstance not found", msg


def _client_error(fn):
    """Return (code, message) of the ClientError fn() raises; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected DescribeStackInstance to be rejected, but the call succeeded")


def _instance_absent(cfn, stackset_name, account_id, region):
    """True once DescribeStackInstance reports the instance as not found."""
    try:
        cfn.describe_stack_instance(
            StackSetName=stackset_name, StackInstanceAccount=account_id, StackInstanceRegion=region
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "StackInstanceNotFoundException":
            return True
        raise
    return False


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


def _poll_op_terminal(cfn, stackset_name, op_id, *, timeout_s=420.0, interval_s=10.0):
    def _probe():
        return cfn.describe_stack_set_operation(StackSetName=stackset_name, OperationId=op_id)[
            "StackSetOperation"
        ]

    op = _poll_until(
        _probe, lambda o: o["Status"] in ("SUCCEEDED", "FAILED", "STOPPED"), timeout_s=timeout_s, interval_s=interval_s
    )
    return op["Status"], op.get("StatusReason", "")


def _create_stack_instance_retrying(cfn, stackset_name, account_id, region, *, timeout_s=90.0, interval_s=15.0):
    """CreateStackInstances, retrying while a freshly created role's trust relationship
    propagates through IAM. That propagation delay surfaces as an async operation
    FAILURE (StackSets assumes the role well after this call returns), not a
    synchronous ClientError, so the retry wraps the whole create-then-poll attempt."""
    deadline = time.monotonic() + timeout_s
    while True:
        op_id = cfn.create_stack_instances(
            StackSetName=stackset_name, Accounts=[account_id], Regions=[region]
        )["OperationId"]
        status, reason = _poll_op_terminal(cfn, stackset_name, op_id)
        if status == "SUCCEEDED" or time.monotonic() >= deadline:
            return status, reason
        time.sleep(interval_s)


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
        admin_role = iam.create_role(RoleName=admin_role_name, AssumeRolePolicyDocument=admin_trust)["Role"]
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
        _create_exec_role_retrying(iam, exec_role_name, exec_trust)

    return admin_role["Arn"], exec_role_name


def _create_exec_role_retrying(iam, exec_role_name, exec_trust, *, timeout_s=60.0, interval_s=5.0):
    """CreateRole for the execution role, retrying while the just-created administration
    role's ARN propagates far enough to be accepted as a trust-policy principal (IAM
    otherwise raises MalformedPolicyDocument for a principal that exists but isn't yet
    visible everywhere)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iam.create_role(RoleName=exec_role_name, AssumeRolePolicyDocument=exec_trust)
            iam.attach_role_policy(RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
