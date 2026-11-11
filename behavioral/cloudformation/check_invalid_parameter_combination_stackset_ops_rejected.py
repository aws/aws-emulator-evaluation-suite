"""invalid-parameter-combination-stackset-ops-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-parameter-combination-stackset-ops-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStackInstances with both Accounts and DeploymentTargets fails with ValidationError
    on a real stack set; DescribeOrganizationsAccess(CallAs=DELEGATED_ADMIN) from an account that
    is not a delegated administrator fails with InvalidOperationException."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    stack_set_name = ctx.unique_name("sim2real-ss-invop-")
    template = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})
    cfn.create_stack_set(
        StackSetName=stack_set_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_stack_set(cfn, stack_set_name))

    error = _client_error(
        lambda: cfn.create_stack_instances(
            StackSetName=stack_set_name,
            Accounts=[account],
            DeploymentTargets={"OrganizationalUnitIds": ["ou-fake-12345678"]},
            Regions=[ctx.region],
        )
    )
    assert error.get("Code") == "ValidationError", f"expected ValidationError, got {error!r}"
    assert error.get("Message") == "Cannot specify both Accounts and DeploymentTargets", (
        f"expected message 'Cannot specify both Accounts and DeploymentTargets', got {error!r}"
    )

    error2 = _client_error(lambda: cfn.describe_organizations_access(CallAs="DELEGATED_ADMIN"))
    assert error2.get("Code") == "InvalidOperationException", (
        f"DescribeOrganizationsAccess(CallAs=DELEGATED_ADMIN) from a non-delegated-admin "
        f"account: expected InvalidOperationException, got {error2!r}"
    )
    assert error2.get("Message") == "Account used is not a delegated administrator", (
        f"expected message 'Account used is not a delegated administrator', got {error2!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_stack_set(cfn, stack_set_name):
    try:
        cfn.delete_stack_set(StackSetName=stack_set_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
