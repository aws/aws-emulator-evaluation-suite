"""stackset-not-found-error-across-apis."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stackset-not-found-error-across-apis"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack set name that was never created returns StackSetNotFoundException
    consistently across every describe/list StackSet API."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    bogus = ctx.unique_name("sim2real-nostackset-")
    bogus_op = str(uuid.uuid4())

    checks = [
        (
            "DescribeStackSetOperation",
            lambda: cfn.describe_stack_set_operation(StackSetName=bogus, OperationId=bogus_op),
        ),
        ("GetTemplateSummary", lambda: cfn.get_template_summary(StackSetName=bogus)),
        ("ListStackInstances", lambda: cfn.list_stack_instances(StackSetName=bogus)),
        (
            "ListStackSetAutoDeploymentTargets",
            lambda: cfn.list_stack_set_auto_deployment_targets(StackSetName=bogus),
        ),
        (
            "ListStackSetOperationResults",
            lambda: cfn.list_stack_set_operation_results(StackSetName=bogus, OperationId=bogus_op),
        ),
        ("ListStackSetOperations", lambda: cfn.list_stack_set_operations(StackSetName=bogus)),
        (
            "DescribeStackInstance",
            lambda: cfn.describe_stack_instance(
                StackSetName=bogus, StackInstanceAccount=account, StackInstanceRegion=ctx.region
            ),
        ),
    ]
    expected = ("StackSetNotFoundException", f"StackSet {bogus} not found")
    for label, fn in checks:
        error = _error(fn, label)
        assert error == expected, (
            f"{label}(StackSetName=<nonexistent>): expected {expected!r}, got {error!r}"
        )


def _error(fn, label):
    """(Error.Code, Error.Message) of the rejection fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"{label}(StackSetName=<nonexistent>): expected a rejection, but it SUCCEEDED "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
