"""update-stack-set-without-instances-updates-in-place."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-stack-set-without-instances-updates-in-place"
GROUP = "stack-sets"
SERVICES = ["cloudformation"]


def _template(description: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": description,
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    })


def _wait_operation(cfn, ss_name, operation_id, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stack_set_operation(
            StackSetName=ss_name, OperationId=operation_id
        )["StackSetOperation"]["Status"]
        if last in {"SUCCEEDED", "FAILED", "STOPPED"}:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack set operation {operation_id!r} did not reach a terminal status in {timeout_s}s (last={last!r})"
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStackSet on a stack set with zero stack instances replaces its description and
    template in place, keeping the same StackSetId and ACTIVE status."""
    cfn = ctx.client("cloudformation")
    ss_name = ctx.unique_name("sim2real-cfn-ssupdate-")
    desc_v1, desc_v2 = "sim2real check v1", "sim2real check v2"

    created = cfn.create_stack_set(StackSetName=ss_name, Description=desc_v1, TemplateBody=_template(desc_v1))
    stack_set_id = created["StackSetId"]
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=ss_name))

    instances = cfn.list_stack_instances(StackSetName=ss_name).get("Summaries", [])
    assert instances == [], f"expected zero stack instances before update, got {instances}"

    before = cfn.describe_stack_set(StackSetName=ss_name)["StackSet"]
    assert before["Description"] == desc_v1, f"expected Description {desc_v1!r}, got {before['Description']!r}"
    assert before["TemplateBody"] == _template(desc_v1), (
        f"expected the template as created, got {before['TemplateBody']!r}"
    )

    operation_id = cfn.update_stack_set(
        StackSetName=ss_name, Description=desc_v2, TemplateBody=_template(desc_v2)
    )["OperationId"]
    op_status = _wait_operation(cfn, ss_name, operation_id)
    assert op_status == "SUCCEEDED", f"the update operation ended {op_status!r}, expected SUCCEEDED"

    after = cfn.describe_stack_set(StackSetName=ss_name)["StackSet"]
    assert after["StackSetId"] == stack_set_id, (
        f"update must not change the StackSetId, got {after['StackSetId']!r} vs {stack_set_id!r}"
    )
    assert after["Description"] == desc_v2, f"expected Description {desc_v2!r}, got {after['Description']!r}"
    assert after["TemplateBody"] == _template(desc_v2), (
        f"expected the updated template body, got {after['TemplateBody']!r}"
    )
    assert after["Status"] == "ACTIVE", f"expected Status ACTIVE after update, got {after['Status']!r}"

    # Independent read: ListStackSets still lists exactly this one stack set by this name.
    page = cfn.get_paginator("list_stack_sets").paginate(Status="ACTIVE")
    names = [s["StackSetName"] for page_ in page for s in page_["Summaries"]]
    assert ss_name in names, f"expected {ss_name!r} among ACTIVE stack sets, got {names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
