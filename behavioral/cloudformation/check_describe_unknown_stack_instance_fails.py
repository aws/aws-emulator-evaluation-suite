"""describe-unknown-stack-instance-fails."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-unknown-stack-instance-fails"
GROUP = 'stack_sets'
SERVICES = ['cloudformation']


def _expect_error(fn):
    """Call fn(); return the raised ClientError. An unexpected success raises, so a target that
    accepts a call AWS refuses fails as an acceptance rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _instance_gone(cf, name, account, region):
    """True once DescribeStackInstance answers StackInstanceNotFoundException."""
    try:
        cf.describe_stack_instance(
            StackSetName=name, StackInstanceAccount=account, StackInstanceRegion=region
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "StackInstanceNotFoundException":
            return True
        raise
    return False


def _poll_until(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _ensure_stackset_roles(ctx):
    """Bootstrap the standard self-managed StackSets admin/execution roles if absent.

    These are the documented fixed-name, account-wide roles for self-managed permissions, set up
    once per account, so cleanup leaves them in place.
    """
    iam = ctx.client("iam")
    admin_role_name = "AWSCloudFormationStackSetAdministrationRole"
    exec_role_name = "AWSCloudFormationStackSetExecutionRole"

    admin_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    })
    created_any = False
    try:
        admin_role = iam.get_role(RoleName=admin_role_name)["Role"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
        admin_role = iam.create_role(RoleName=admin_role_name, AssumeRolePolicyDocument=admin_trust)["Role"]
        iam.put_role_policy(
            RoleName=admin_role_name,
            PolicyName="AssumeStackSetExecRole",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::*:role/{exec_role_name}"}
                ],
            }),
        )
        created_any = True

    exec_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_role["Arn"]}, "Action": "sts:AssumeRole"}],
    })
    try:
        iam.get_role(RoleName=exec_role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
        # A just-created role ARN is not always immediately valid as another policy's
        # Principal -- IAM rejects it as MalformedPolicyDocument until the new role has
        # propagated. Bounded retry on that specific error, not a blind sleep.
        deadline = time.monotonic() + 60.0
        while True:
            try:
                iam.create_role(RoleName=exec_role_name, AssumeRolePolicyDocument=exec_trust)
                break
            except ClientError as create_exc:
                if create_exc.response["Error"]["Code"] != "MalformedPolicyDocument" or (
                    time.monotonic() >= deadline
                ):
                    raise
                time.sleep(5)
        iam.attach_role_policy(RoleName=exec_role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        created_any = True

    return admin_role["Arn"], exec_role_name, created_any


def _create_stack_instances_with_role_propagation(cf, name, account, region, *, retry_deadline):
    """create_stack_instances + poll to a terminal status, retrying a FAILED operation until
    retry_deadline. Freshly-created admin/exec roles are not always immediately assumable by
    StackSets, and that surfaces as the async operation ending FAILED, not as an exception on
    the call itself -- so the bounded wait has to wrap the whole create+poll, not precede it."""
    last_status = None
    while True:
        op_id = cf.create_stack_instances(StackSetName=name, Accounts=[account], Regions=[region])[
            "OperationId"
        ]
        status = _poll_until(
            lambda: cf.describe_stack_set_operation(StackSetName=name, OperationId=op_id)
            ["StackSetOperation"]["Status"],
            lambda s: s in ("SUCCEEDED", "FAILED", "STOPPED"),
            timeout_s=420,
            description="create_stack_instances operation",
        )
        if status == "SUCCEEDED":
            return op_id
        last_status = status
        if time.monotonic() >= retry_deadline:
            raise AssertionError(
                f"create_stack_instances ended as {last_status} even after waiting for "
                "IAM role propagation"
            )
        time.sleep(2)


def _topic_template(topic_name=None, extra_tag=None):
    props = {}
    if topic_name:
        props["TopicName"] = topic_name
    if extra_tag:
        props["Tags"] = [{"Key": "probe", "Value": extra_tag}]
    return json.dumps({
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": props}},
        "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
    })


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStackInstance for a region the stack set was never deployed to fails with
    StackInstanceNotFoundException "StackInstance not found", while the same call for the region
    it is deployed to succeeds with Status CURRENT."""
    cf = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]
    deployed_region = ctx.region
    # DescribeStackInstance only needs a well-formed region string; it does not require the
    # region to be enabled or resolvable. A second, never-targeted region is the cheapest twin
    # control -- same stack set, same instant, only the region differs.
    absent_region = "us-east-1" if deployed_region != "us-east-1" else "eu-west-1"

    admin_arn, exec_role_name, roles_created = _ensure_stackset_roles(ctx)

    name = ctx.unique_name("sim2real-behav-ss-unk-")
    cf.create_stack_set(
        StackSetName=name,
        TemplateBody=_topic_template(),
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_role_name,
    )

    def _cleanup():
        try:
            cf.delete_stack_instances(
                StackSetName=name, Accounts=[account], Regions=[deployed_region], RetainStacks=False
            )
            _poll_until(
                lambda: _instance_gone(cf, name, account, deployed_region),
                lambda gone: gone,
                timeout_s=300,
                description="stack instance teardown",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "OperationNotFoundException",
                "StackInstanceNotFoundException",
                "StackSetNotFoundException",
            ):
                raise
        try:
            cf.delete_stack_set(StackSetName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StackSetNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # Positive control: deploy a real instance into this stack set first, so the target's
    # baseline DescribeStackInstance behaviour is established before we probe the region it
    # was never asked to touch. Bound the FAILED-retry window to 90s only when we just minted
    # the roles ourselves; a pre-existing role that still fails gets no grace.
    retry_deadline = time.monotonic() + (90.0 if roles_created else 0.0)
    _create_stack_instances_with_role_propagation(
        cf, name, account, deployed_region, retry_deadline=retry_deadline
    )

    deployed = cf.describe_stack_instance(
        StackSetName=name, StackInstanceAccount=account, StackInstanceRegion=deployed_region
    )["StackInstance"]
    assert deployed["Status"] == "CURRENT", deployed

    # Negative: same StackSetName, same account, a region CreateStackInstances was never
    # called for.
    err = _expect_error(
        lambda: cf.describe_stack_instance(
            StackSetName=name, StackInstanceAccount=account, StackInstanceRegion=absent_region
        )
    ).response["Error"]
    assert err["Code"] == "StackInstanceNotFoundException", (
        f"expected StackInstanceNotFoundException, got {err['Code']}"
    )
    assert err.get("Message") == "StackInstance not found", (
        f"expected message 'StackInstance not found', got {err.get('Message')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
