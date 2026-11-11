"""create-stack-circular-dependson-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-stack-circular-dependson-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudformation"]


def _cyclic_template() -> str:
    return json.dumps(
        {
            "Resources": {
                "TopicA": {"Type": "AWS::SNS::Topic", "DependsOn": "TopicB"},
                "TopicB": {"Type": "AWS::SNS::Topic", "DependsOn": "TopicA"},
            }
        }
    )


def _acyclic_template() -> str:
    return json.dumps(
        {
            "Resources": {
                "TopicA": {"Type": "AWS::SNS::Topic"},
                "TopicB": {"Type": "AWS::SNS::Topic", "DependsOn": "TopicA"},
            }
        }
    )


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A template with a circular DependsOn chain is rejected synchronously at CreateStack
    time (never enters CREATE_IN_PROGRESS), while the same template with the cycle broken
    creates successfully and provisions real, independently-readable resources."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-cfn-cycle-")

    err = _client_error(lambda: cfn.create_stack(StackName=name, TemplateBody=_cyclic_template()))
    assert err.get("Code") == "ValidationError", f"expected ValidationError, got {err}"
    expected = "Circular dependency between resources: [TopicB, TopicA]"
    assert err.get("Message") == expected, (
        f"the rejection must identify the circular dependency, expected {expected!r}, "
        f"got {err.get('Message')!r}"
    )

    # (b) effect absent: no stack was ever created for this name
    nf_err = _client_error(lambda: cfn.describe_stacks(StackName=name))
    assert nf_err.get("Code") == "ValidationError", f"expected stack-not-found ValidationError, got {nf_err}"
    assert nf_err.get("Message") == f"Stack with id {name} does not exist", (
        f"expected the exact stack-not-found message, got {nf_err.get('Message')!r}"
    )

    # (c) positive control: the same two resources without the cycle create successfully
    cfn.create_stack(StackName=name, TemplateBody=_acyclic_template())
    ctx.on_cleanup(lambda: _safe_delete_stack(ctx, name))
    _wait_stack_status(ctx, name, {"CREATE_COMPLETE"})

    # (d) terminal read independent of CloudFormation's own status word: the topics the
    # accepted template declared are real, addressable SNS resources, not just a CFN report.
    resources = cfn.describe_stack_resources(StackName=name)["StackResources"]
    arns = {r["LogicalResourceId"]: r["PhysicalResourceId"] for r in resources}
    assert set(arns) == {"TopicA", "TopicB"}, f"expected TopicA and TopicB, got {sorted(arns)}"
    for logical_id, arn in arns.items():
        attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
        assert attrs.get("TopicArn") == arn, (
            f"{logical_id} ({arn}) not independently readable via SNS: {attrs}"
        )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe_delete_stack(ctx, name):
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _wait_stack_status(ctx, name, terminal_statuses, timeout_s=180.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=name)["Stacks"]
        last = stacks[0]["StackStatus"]
        if last in terminal_statuses:
            return last
        if last.endswith("FAILED") or "ROLLBACK" in last:
            raise AssertionError(f"stack {name} entered unexpected status {last}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {name} never reached {terminal_statuses}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
