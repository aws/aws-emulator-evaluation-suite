"""get-template-summary-stackset-not-found."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-template-summary-stackset-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTemplateSummary against a real StackSet succeeds (positive control); against a
    nonexistent StackSetName it returns StackSetNotFoundException specifically, not a
    blanket rejection of the operation."""
    cfn = ctx.client("cloudformation")

    ss_name = ctx.unique_name("sim2real-behav-ss-")
    queue_name = ctx.unique_name("sim2real-behav-ssq-")
    cfn.create_stack_set(
        StackSetName=ss_name,
        TemplateBody=json.dumps(
            {"Resources": {"Q": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name}}}}
        ),
    )
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=ss_name))

    summary = cfn.get_template_summary(StackSetName=ss_name)
    resource_types = summary.get("ResourceTypes", [])
    assert "AWS::SQS::Queue" in resource_types, (
        f"positive control: expected AWS::SQS::Queue in ResourceTypes, got {resource_types!r}"
    )

    bogus_stackset_name = ctx.unique_name("sim2real-behav-noss-")
    error = _client_error(lambda: cfn.get_template_summary(StackSetName=bogus_stackset_name))
    assert error.get("Code") == "StackSetNotFoundException", f"expected StackSetNotFoundException, got {error!r}"
    expected_message = f"StackSet {bogus_stackset_name} not found"
    assert error.get("Message") == expected_message, f"expected message {expected_message!r}, got {error!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
