"""stackset-create-duplicate-name-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stackset-create-duplicate-name-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a StackSet with a name that already exists returns NameAlreadyExistsException,
    the rejected duplicate leaves the existing StackSet untouched, and the name becomes usable
    again once the original StackSet is actually deleted."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")

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

    stackset_name = ctx.unique_name("sim2real-stackset-dup-")
    create_kwargs = dict(
        StackSetName=stackset_name,
        TemplateBody=_TEMPLATE,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_role_arn,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    original_id = cfn.create_stack_set(**create_kwargs)["StackSetId"]
    ctx.on_cleanup(lambda: _delete_stack_set(cfn, stackset_name))

    code, msg = _client_error(lambda: cfn.create_stack_set(**create_kwargs))
    assert code == "NameAlreadyExistsException", f"expected NameAlreadyExistsException, got {code}"
    assert msg == "StackSet already exists.", msg

    # Independent read through a different operation than the one that mutated: the rejected
    # duplicate must not have replaced or altered the original StackSet.
    described = cfn.describe_stack_set(StackSetName=stackset_name)["StackSet"]
    assert described["StackSetId"] == original_id, (
        f"rejected duplicate create appears to have replaced the StackSet: "
        f"original={original_id!r}, now={described['StackSetId']!r}"
    )
    assert described["Status"] == "ACTIVE", f"expected ACTIVE, got {described['Status']!r}"

    # Restore leg: the name is rejected only while it is in use by a live StackSet -- delete the
    # original, prove it is actually gone via an independent read, then the identical call must
    # now succeed against a fresh StackSet.
    cfn.delete_stack_set(StackSetName=stackset_name)
    _wait_stack_set_gone(cfn, stackset_name)

    recreated_id = cfn.create_stack_set(**create_kwargs)["StackSetId"]
    assert recreated_id != original_id, (
        f"expected a fresh StackSetId after delete+recreate, got the original id {recreated_id!r} back"
    )
    recreated = cfn.describe_stack_set(StackSetName=stackset_name)["StackSet"]
    assert recreated["Status"] == "ACTIVE", (
        f"recreated stack set {stackset_name} did not come up ACTIVE, got {recreated['Status']!r}"
    )


def _client_error(fn):
    """Return (code, message) of the ClientError fn() raises; raise AssertionError if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the duplicate CreateStackSet to be rejected, but it succeeded")


def _wait_stack_set_gone(cfn, stackset_name, timeout_s=60.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cfn.describe_stack_set(StackSetName=stackset_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "StackSetNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack set {stackset_name} did not become not-found within {timeout_s}s")
        time.sleep(interval_s)


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
