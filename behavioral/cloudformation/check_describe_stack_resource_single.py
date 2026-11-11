"""describe-stack-resource-single."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "describe-stack-resource-single"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStackResource for a logical id returns the same physical id and
    status as the matching entry in the plural DescribeStackResources call."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-dsr-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda status: status == "CREATE_COMPLETE",
        timeout_s=120.0,
        interval_s=5.0,
    )

    single = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Topic")[
        "StackResourceDetail"
    ]
    plural = cfn.describe_stack_resources(StackName=stack_name, LogicalResourceId="Topic")[
        "StackResources"
    ]
    assert len(plural) == 1, f"expected exactly one matching resource, got {plural}"
    plural_entry = plural[0]

    assert single["LogicalResourceId"] == plural_entry["LogicalResourceId"] == "Topic", (
        f"expected LogicalResourceId 'Topic' on both reads, "
        f"got single={single['LogicalResourceId']!r} plural={plural_entry['LogicalResourceId']!r}"
    )
    assert single["PhysicalResourceId"] == plural_entry["PhysicalResourceId"], (
        f"single and plural disagree on PhysicalResourceId: "
        f"single={single['PhysicalResourceId']!r} plural={plural_entry['PhysicalResourceId']!r}"
    )
    assert single["ResourceType"] == plural_entry["ResourceType"] == "AWS::SNS::Topic", (
        f"expected ResourceType 'AWS::SNS::Topic' on both reads, "
        f"got single={single['ResourceType']!r} plural={plural_entry['ResourceType']!r}"
    )
    assert single["ResourceStatus"] == plural_entry["ResourceStatus"] == "CREATE_COMPLETE", (
        f"expected ResourceStatus 'CREATE_COMPLETE' on both reads, "
        f"got single={single['ResourceStatus']!r} plural={plural_entry['ResourceStatus']!r}"
    )


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
