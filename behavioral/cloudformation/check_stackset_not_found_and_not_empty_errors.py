"""stackset-not-found-and-not-empty-errors."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stackset-not-found-and-not-empty-errors"
GROUP = 'stack_sets'
SERVICES = ['cloudformation']


def _expect_error(fn, expected):
    """Assert fn() raises a ClientError whose (Error.Code, Error.Message) is exactly *expected*. An
    unexpected success raises, so a target that accepts a call AWS refuses fails as an
    acceptance rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = (exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message"))
        assert error == expected, f"expected {expected!r}, got {error!r}"
        return error
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _sns_template(tags=None):
    props = {}
    if tags:
        props["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]
    return json.dumps(
        {
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": props}},
            "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
        }
    )

def _wait_stackset_operation(cf, ss_name, op_id, targets, timeout_s=300):
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = cf.describe_stack_set_operation(StackSetName=ss_name, OperationId=op_id)[
            "StackSetOperation"
        ]
        if op.get("Status") in targets:
            return op
        time.sleep(5)
    raise AssertionError(f"StackSet operation {op_id} did not reach {targets} within {timeout_s}s: {op!r}")

def _retry_until(fn, timeout_s, reason, interval_s=5.0):
    """Retry fn() on ClientError until it succeeds or timeout_s elapses, then re-raise.

    For genuine AWS-side eventual consistency (`reason`) only — never a substitute for
    asserting an expected failure, since the final failure always propagates.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

def _deploy_stack_instance(cf, ss_name, account_id, region, timeout_s=120, interval_s=10):
    """Create a stack instance, retrying while CloudFormation reports the exec role's trust
    relationship to the admin role as not yet visible ("Account ... should have '...' role with
    trust relationship to Role '...'"); this IAM propagation lag is slower than the
    CreateStackSet-time role/policy lag `_retry_until` covers."""
    deadline = time.monotonic() + timeout_s
    while True:
        op = cf.create_stack_instances(StackSetName=ss_name, Accounts=[account_id], Regions=[region])
        result = _wait_stackset_operation(cf, ss_name, op["OperationId"], {"SUCCEEDED", "FAILED", "STOPPED"})
        if result["Status"] == "SUCCEEDED" or time.monotonic() >= deadline:
            return result
        # The account/region pair is already tracked by the failed attempt; tear it down
        # before retrying, or the next CreateStackInstances rejects it as a duplicate.
        del_op = cf.delete_stack_instances(
            StackSetName=ss_name, Accounts=[account_id], Regions=[region], RetainStacks=False
        )
        _wait_stackset_operation(cf, ss_name, del_op["OperationId"], {"SUCCEEDED", "FAILED", "STOPPED"})
        time.sleep(interval_s)

def _setup_self_managed_roles(ctx):
    """Create a throwaway admin/exec role pair for SELF_MANAGED StackSets.
    Returns (admin_role_arn, exec_role_name); both tracked for teardown."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    admin_name = ctx.unique_name("sim2real-behav-cfn-admin-")
    exec_name = ctx.unique_name("sim2real-behav-cfn-exec-")

    admin_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudformation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    admin_role = iam.create_role(
        RoleName=admin_name, AssumeRolePolicyDocument=json.dumps(admin_trust)
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=admin_name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole"))

    exec_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:role/{admin_name}"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    # IAM read-after-write lag: the trust policy above references the admin ARN as a
    # Principal, which IAM validates for existence at CreateRole time — a role just
    # created is not always visible to that check yet. Bounded retry, not a blind sleep.
    _retry_until(
        lambda: iam.create_role(RoleName=exec_name, AssumeRolePolicyDocument=json.dumps(exec_trust)),
        timeout_s=60,
        reason="IAM read-after-write lag on the admin role Principal",
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_name))
    iam.attach_role_policy(
        RoleName=exec_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=exec_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
        )
    )
    assume_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": f"arn:aws:iam::{account_id}:role/{exec_name}",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=admin_name, PolicyName="AssumeExecRole", PolicyDocument=json.dumps(assume_policy)
    )
    return admin_role["Role"]["Arn"], exec_name


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStackSet/GetTemplateSummary on an unknown StackSet fail with StackSetNotFoundException
    "StackSet <name> not found"; DeleteStackSet with a deployed instance fails with StackSetNotEmptyException
    "StackSet is not empty", leaves the StackSet ACTIVE, and succeeds once the instance is gone."""
    cf = ctx.client("cloudformation")
    missing_name = ctx.unique_name("sim2real-behav-stackset-missing-")

    missing_message = f"StackSet {missing_name} not found"
    _expect_error(lambda: cf.describe_stack_set(StackSetName=missing_name), ("StackSetNotFoundException", missing_message))
    _expect_error(lambda: cf.get_template_summary(StackSetName=missing_name), ("StackSetNotFoundException", missing_message))

    # The not-empty case needs a deployed stack instance, and so a SELF_MANAGED admin/exec
    # IAM assume-role chain; a target that cannot deploy an instance cannot raise
    # StackSetNotEmptyException either, so every target is asked for it.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-stackset-nonempty-")
    admin_arn, exec_name = _setup_self_managed_roles(ctx)

    def _create_stack_set():
        cf.create_stack_set(
            StackSetName=name,
            TemplateBody=_sns_template(),
            PermissionModel="SELF_MANAGED",
            AdministrationRoleARN=admin_arn,
            ExecutionRoleName=exec_name,
        )

    # CreateStackSet assumes AdministrationRoleARN immediately, and the role/policy
    # pair above needs a moment for IAM's read-after-write lag to clear before
    # CloudFormation can assume it. Bounded retry, not a blind sleep.
    _retry_until(_create_stack_set, timeout_s=60, reason="IAM role/policy propagation")

    deleted = {"stack_set": False, "instances": False}
    ctx.on_cleanup(lambda: None if deleted["stack_set"] else cf.delete_stack_set(StackSetName=name))

    # ---- positive control: the same two calls that reject an unknown name succeed
    # against the real, just-created StackSet ----
    described = cf.describe_stack_set(StackSetName=name)["StackSet"]
    assert described["StackSetName"] == name, f"describe_stack_set returned the wrong set: {described!r}"
    summary = cf.get_template_summary(StackSetName=name)
    assert "Version" in summary, f"get_template_summary did not return a template summary: {summary!r}"

    # ---- break exactly one thing: attach a live stack instance ----
    ctx.on_cleanup(
        lambda: None
        if deleted["instances"]
        else cf.delete_stack_instances(
            StackSetName=name, Accounts=[account_id], Regions=[ctx.region], RetainStacks=False
        )
    )
    create_op = _deploy_stack_instance(cf, name, account_id, ctx.region)
    if create_op["Status"] != "SUCCEEDED":
        instances = cf.list_stack_instances(StackSetName=name)["Summaries"]
        assert False, (
            f"stack instance deployment did not succeed, cannot exercise StackSetNotEmpty: "
            f"{create_op!r} instances={instances!r}"
        )

    # ---- assert the specific error code ----
    _expect_error(lambda: cf.delete_stack_set(StackSetName=name), ("StackSetNotEmptyException", "StackSet is not empty"))

    # ---- effect absent via an independent read: the StackSet is still there ----
    still_there = cf.describe_stack_set(StackSetName=name)["StackSet"]
    assert still_there["Status"] == "ACTIVE", (
        f"StackSet {name} should still be ACTIVE after the refused delete: {still_there!r}"
    )

    # ---- restore: remove the blocking stack instance ----
    del_op = cf.delete_stack_instances(
        StackSetName=name, Accounts=[account_id], Regions=[ctx.region], RetainStacks=False
    )
    del_result = _wait_stackset_operation(cf, name, del_op["OperationId"], {"SUCCEEDED", "FAILED", "STOPPED"})
    assert del_result["Status"] == "SUCCEEDED", f"removing the stack instance did not succeed: {del_result!r}"
    deleted["instances"] = True

    # ---- the identical call now succeeds, and the StackSet is gone for good ----
    cf.delete_stack_set(StackSetName=name)
    deleted["stack_set"] = True
    _expect_error(lambda: cf.describe_stack_set(StackSetName=name), ("StackSetNotFoundException", f"StackSet {name} not found"))

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
