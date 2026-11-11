"""stackset-not-found-across-apis-rejected."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stackset-not-found-across-apis-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A never-existing StackSetName returns StackSetNotFoundException across describe/list
    APIs; an existing stack set through the same APIs is the positive control."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    real_name = ctx.unique_name("sim2real-realstackset-")
    cfn.create_stack_set(StackSetName=real_name, TemplateBody=_TEMPLATE)
    ctx.on_cleanup(lambda: _safe_delete_stack_set(cfn, real_name))
    # A real OperationId to positive-control DescribeStackSetOperation / ListStackSetOperationResults;
    # UpdateStackSet still runs (and completes immediately) even with zero deployed instances.
    real_op_id = cfn.update_stack_set(StackSetName=real_name, TemplateBody=_TEMPLATE)["OperationId"]

    bogus_name = ctx.unique_name("sim2real-nostackset-")
    bogus_op_id = str(uuid.uuid4())

    checks = [
        (
            "DescribeStackSetOperation",
            lambda: cfn.describe_stack_set_operation(StackSetName=real_name, OperationId=real_op_id),
            lambda: cfn.describe_stack_set_operation(StackSetName=bogus_name, OperationId=bogus_op_id),
        ),
        (
            "GetTemplateSummary",
            lambda: cfn.get_template_summary(StackSetName=real_name),
            lambda: cfn.get_template_summary(StackSetName=bogus_name),
        ),
        (
            "ListStackInstances",
            lambda: cfn.list_stack_instances(StackSetName=real_name),
            lambda: cfn.list_stack_instances(StackSetName=bogus_name),
        ),
        (
            "ListStackSetAutoDeploymentTargets",
            lambda: cfn.list_stack_set_auto_deployment_targets(StackSetName=real_name),
            lambda: cfn.list_stack_set_auto_deployment_targets(StackSetName=bogus_name),
        ),
        (
            "ListStackSetOperationResults",
            lambda: cfn.list_stack_set_operation_results(StackSetName=real_name, OperationId=real_op_id),
            lambda: cfn.list_stack_set_operation_results(StackSetName=bogus_name, OperationId=bogus_op_id),
        ),
        (
            "ListStackSetOperations",
            lambda: cfn.list_stack_set_operations(StackSetName=real_name),
            lambda: cfn.list_stack_set_operations(StackSetName=bogus_name),
        ),
        (
            "DescribeStackInstance",
            lambda: cfn.describe_stack_instance(
                StackSetName=real_name, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
            ),
            lambda: cfn.describe_stack_instance(
                StackSetName=bogus_name, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
            ),
        ),
    ]
    expected = ("StackSetNotFoundException", f"StackSet {bogus_name} not found")
    for label, positive_fn, negative_fn in checks:
        try:
            positive_fn()
        except ClientError as exc:
            assert exc.response["Error"]["Code"] != "StackSetNotFoundException", (
                f"{label} against a real, existing stack set returned StackSetNotFoundException "
                f"-- the target cannot be discriminating existing from nonexistent"
            )
        negative = _error(negative_fn)
        assert negative == expected, f"{label} returned {negative!r}, expected {expected!r}"


def _error(fn):
    """(Error.Code, Error.Message) of the rejection fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_stack_set(cfn, name):
    try:
        cfn.delete_stack_set(StackSetName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
