"""get-template-summary-stackset-not-found-error."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-template-summary-stackset-not-found-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTemplateSummary succeeds against a real StackSet (positive control), then raises
    StackSetNotFoundException once that same name is perturbed into one that was never created."""
    cfn = ctx.client("cloudformation")
    real_name = ctx.unique_name("sim2real-behav-stackset-")
    cfn.create_stack_set(
        StackSetName=real_name,
        TemplateBody=_queue_template(ctx.unique_name("sim2real-behav-ssq-")),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=real_name))

    resp = cfn.get_template_summary(StackSetName=real_name)
    assert resp.get("ResourceTypes"), f"positive control: expected ResourceTypes, got {resp!r}"

    bogus_stackset_name = real_name + "-absent"
    error = _client_error(lambda: cfn.get_template_summary(StackSetName=bogus_stackset_name))
    assert error.get("Code") == "StackSetNotFoundException", f"expected StackSetNotFoundException, got {error!r}"
    expected_message = f"StackSet {bogus_stackset_name} not found"
    assert error.get("Message") == expected_message, f"expected message {expected_message!r}, got {error!r}"


def _queue_template(queue_name):
    return json.dumps(
        {"Resources": {"Q": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name}}}}
    )


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
