"""describe-stack-instance-not-found-error."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-stack-instance-not-found-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStackInstance on an existing StackSet with no matching instance returns StackInstanceNotFoundException."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    admin_role_name = ctx.unique_name("sim2real-cfn-admin-")
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
    admin_role_arn = iam.create_role(
        RoleName=admin_role_name, AssumeRolePolicyDocument=json.dumps(admin_trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, admin_role_name))

    stackset_name = ctx.unique_name("sim2real-stackset-noinstance-")
    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=_TEMPLATE,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_role_arn,
    )
    ctx.on_cleanup(lambda: _delete_stack_set(cfn, stackset_name))

    err = _expect_error(
        lambda: cfn.describe_stack_instance(
            StackSetName=stackset_name,
            StackInstanceAccount=account_id,
            StackInstanceRegion=ctx.region,
        )
    ).response["Error"]
    assert err["Code"] == "StackInstanceNotFoundException", (
        f"expected StackInstanceNotFoundException, got {err['Code']}"
    )
    assert err.get("Message") == "StackInstance not found", (
        f"expected message 'StackInstance not found', got {err.get('Message')!r}"
    )

    # Independent read through a DIFFERENT operation, corroborating the not-found: if
    # CloudFormation were simply erroring on every call for this StackSet, this list
    # would fail too rather than answering with a real (empty) collection.
    instances = cfn.list_stack_instances(StackSetName=stackset_name).get("Summaries", [])
    assert instances == [], (
        f"expected no stack instances for a StackSet nobody deployed to, got {instances}"
    )


def _expect_error(fn):
    """Call fn(); return the raised ClientError. Raise if fn() succeeds unexpectedly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_role(iam, role_name):
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_stack_set(cfn, stackset_name):
    try:
        cfn.delete_stack_set(StackSetName=stackset_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
