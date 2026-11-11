"""stack-resource-status-and-listing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-resource-status-and-listing"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Individual resource status from DescribeStackResource is consistent with the
    bulk resource listings for the same stack."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-resstatus-")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Topic": {"Type": "AWS::SNS::Topic"},
                "Queue": {"Type": "AWS::SQS::Queue"},
            },
        }
    )
    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))
    _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180)

    single_topic = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Topic")[
        "StackResourceDetail"
    ]
    assert single_topic["ResourceStatus"] == "CREATE_COMPLETE", (
        f"expected Topic CREATE_COMPLETE, got {single_topic['ResourceStatus']!r}"
    )
    single_queue = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Queue")[
        "StackResourceDetail"
    ]
    assert single_queue["ResourceStatus"] == "CREATE_COMPLETE", (
        f"expected Queue CREATE_COMPLETE, got {single_queue['ResourceStatus']!r}"
    )
    singles = {"Topic": single_topic, "Queue": single_queue}

    bulk = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    bulk_by_id = {r["LogicalResourceId"]: r for r in bulk}
    assert bulk_by_id.keys() == {"Topic", "Queue"}, (
        f"expected bulk listing to cover {{'Topic', 'Queue'}}, got {set(bulk_by_id)}"
    )
    for logical_id, single in singles.items():
        bulk_entry = bulk_by_id[logical_id]
        assert bulk_entry["PhysicalResourceId"] == single["PhysicalResourceId"], (
            f"{logical_id}: bulk physical id {bulk_entry['PhysicalResourceId']!r} != "
            f"single physical id {single['PhysicalResourceId']!r}"
        )
        assert bulk_entry["ResourceStatus"] == single["ResourceStatus"], (
            f"{logical_id}: bulk status {bulk_entry['ResourceStatus']!r} != "
            f"single status {single['ResourceStatus']!r}"
        )

    listed = cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    listed_by_id = {r["LogicalResourceId"]: r for r in listed}
    assert listed_by_id.keys() == {"Topic", "Queue"}, (
        f"expected ListStackResources to cover {{'Topic', 'Queue'}}, got {set(listed_by_id)}"
    )
    for logical_id, single in singles.items():
        listed_entry = listed_by_id[logical_id]
        assert listed_entry["PhysicalResourceId"] == single["PhysicalResourceId"], (
            f"{logical_id}: listed physical id {listed_entry['PhysicalResourceId']!r} != "
            f"single physical id {single['PhysicalResourceId']!r}"
        )
        assert listed_entry["ResourceStatus"] == single["ResourceStatus"], (
            f"{logical_id}: listed status {listed_entry['ResourceStatus']!r} != "
            f"single status {single['ResourceStatus']!r}"
        )


def _safe_delete_stack(cfn, stack_name) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _wait_stack_status(cfn, stack_name, terminal_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal_statuses:
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} did not reach {terminal_statuses}, last={status}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
