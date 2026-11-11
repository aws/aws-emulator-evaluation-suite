"""empty-string-vs-absent-parameter-distinguished."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "empty-string-vs-absent-parameter-distinguished"
GROUP = "representation"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A parameter explicitly passed as an empty string is preserved as empty on
    read-back, distinct from a sibling parameter that is omitted entirely and
    therefore falls back to its Default."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-emptyparam-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ExplicitEmpty": {"Type": "String", "Default": "should-be-overridden"},
            "OmittedUsesDefault": {"Type": "String", "Default": "the-default-value"},
        },
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        # ExplicitEmpty is passed as "" on purpose; OmittedUsesDefault is not
        # passed at all, so CloudFormation must fall back to its Default.
        Parameters=[{"ParameterKey": "ExplicitEmpty", "ParameterValue": ""}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE"}, timeout_s=120)

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    params = {p["ParameterKey"]: p["ParameterValue"] for p in stack["Parameters"]}

    assert params["ExplicitEmpty"] == "", (
        f"explicit empty-string parameter was not preserved: {params['ExplicitEmpty']!r}"
    )
    assert params["OmittedUsesDefault"] == "the-default-value", (
        f"omitted parameter did not fall back to its Default: {params['OmittedUsesDefault']!r}"
    )


def _wait_for_stack_status(ctx, stack_name, terminal_statuses, timeout_s=120.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        last = resp["Stacks"][0]["StackStatus"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {terminal_statuses}, last status {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
