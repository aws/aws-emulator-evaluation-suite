"""changeset-create-type-review-in-progress-flow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "changeset-create-type-review-in-progress-flow"
GROUP = 'changeset'
SERVICES = ['cloudformation']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """CreateChangeSet(ChangeSetType=CREATE) materializes the stack in REVIEW_IN_PROGRESS with
    no resources; ExecuteChangeSet then drives it to CREATE_COMPLETE and the change set to
    EXECUTE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cfn-csreview-")
    cs_name = ctx.unique_name("sim2real-behav-cs-")
    tmpl = _sns_topic_template(ctx.unique_name("sim2real-behav-cfn-topic-"))

    resp = cfn.create_change_set(
        StackName=name,
        ChangeSetName=cs_name,
        TemplateBody=tmpl,
        ChangeSetType="CREATE",
    )
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, name))
    # The returned ARN is the change set's stable key for every later call.
    cs_arn = resp["Id"]
    assert cs_arn.startswith("arn:"), cs_arn

    # The REVIEW_IN_PROGRESS stack exists as soon as CreateChangeSet returns, so the
    # (name, stack name) lookup already resolves to the same change set. The rest of the
    # check still uses cs_arn exclusively.
    by_name = cfn.describe_change_set(ChangeSetName=cs_name, StackName=name)
    assert by_name["ChangeSetId"] == cs_arn, (by_name.get("ChangeSetId"), cs_arn)

    cs = _poll_until(
        lambda: cfn.describe_change_set(ChangeSetName=cs_arn),
        lambda r: r.get("Status") in {"CREATE_COMPLETE", "FAILED", "DELETE_COMPLETE"},
        timeout_s=120,
        interval_s=3,
        description="CREATE-type change set reaching a terminal status",
    )
    assert cs["Status"] == "CREATE_COMPLETE", (cs["Status"], cs.get("StatusReason"))
    assert cs["ExecutionStatus"] == "AVAILABLE", cs["ExecutionStatus"]

    # the stack exists but is only a review shell: REVIEW_IN_PROGRESS, zero resources
    review = _describe_stack(cfn, name)
    assert review["StackStatus"] == "REVIEW_IN_PROGRESS", review["StackStatus"]
    resources = cfn.list_stack_resources(StackName=name)["StackResourceSummaries"]
    assert resources == [], resources

    summaries = cfn.list_change_sets(StackName=name)["Summaries"]
    assert cs_name in {s["ChangeSetName"] for s in summaries}, summaries

    cfn.execute_change_set(ChangeSetName=cs_arn)
    final = _wait_stack_status(cfn, name, timeout_s=180)
    assert final["StackStatus"] == "CREATE_COMPLETE", final["StackStatus"]

    executed = cfn.describe_change_set(ChangeSetName=cs_arn)
    assert executed["ExecutionStatus"] == "EXECUTE_COMPLETE", executed["ExecutionStatus"]

    created = cfn.list_stack_resources(StackName=name)["StackResourceSummaries"]
    assert {r["LogicalResourceId"] for r in created} == {"MyTopic"}, created


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _sns_topic_template(topic_name, display_name=None) -> str:
    props = {"TopicName": topic_name}
    if display_name is not None:
        props["DisplayName"] = display_name
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"MyTopic": {"Type": "AWS::SNS::Topic", "Properties": props}},
            "Outputs": {"TopicArnOutput": {"Value": {"Ref": "MyTopic"}}},
        }
    )


def _describe_stack(cfn, name):
    stacks = cfn.describe_stacks(StackName=name).get("Stacks", [])
    assert stacks, f"stack {name} not found"
    return stacks[0]


def _wait_stack_status(cfn, name, timeout_s=180, interval_s=3):
    """Poll DescribeStacks until the stack reaches any terminal status."""
    return _poll_until(
        lambda: _describe_stack(cfn, name),
        lambda stack: stack.get("StackStatus") in _TERMINAL_STACK_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"stack {name} reaching a terminal status",
    )


def _delete_stack_quiet(cfn, name):
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
