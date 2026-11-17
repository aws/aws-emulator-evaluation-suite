"""list-stack-refactor-actions-paginates-by-max-results."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-stack-refactor-actions-paginates-by-max-results"
GROUP = "stack-refactoring"
SERVICES = ["cloudformation"]


def _template(topic_a: str, topic_b: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            topic_a: {"Type": "AWS::SNS::Topic", "Properties": {}},
            topic_b: {"Type": "AWS::SNS::Topic", "Properties": {}},
        },
    })


def _wait_stack(cfn, stack_name, terminal, timeout_s=240.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name!r} did not reach {terminal} in {timeout_s}s (last={last!r})")


def _wait_refactor_status(cfn, refactor_id, terminal, timeout_s=300.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stack_refactor(StackRefactorId=refactor_id)["Status"]
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack refactor {refactor_id!r} did not reach {terminal} in {timeout_s}s (last={last!r})"
    )


def _action_key(action: dict) -> tuple:
    mapping = action.get("ResourceMapping") or {}
    source, destination = mapping.get("Source") or {}, mapping.get("Destination") or {}
    return (
        action["Action"], action["Entity"],
        source.get("LogicalResourceId"), destination.get("LogicalResourceId"),
    )


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStackRefactorActions with MaxResults=1 returns every action exactly once across
    its NextToken pages, matching the single unpaginated page a MaxResults-free call returns."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-refactoractions-")
    old_a, old_b, new_a, new_b = "TopicA", "TopicB", "TopicRenamedA", "TopicRenamedB"

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(old_a, old_b),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    created = _wait_stack(cfn, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})
    assert created == "CREATE_COMPLETE", f"prerequisite stack {stack_name!r} reached {created!r}"

    refactor_id = cfn.create_stack_refactor(
        StackDefinitions=[{"StackName": stack_name, "TemplateBody": _template(new_a, new_b)}],
        ResourceMappings=[
            {
                "Source": {"StackName": stack_name, "LogicalResourceId": old_a},
                "Destination": {"StackName": stack_name, "LogicalResourceId": new_a},
            },
            {
                "Source": {"StackName": stack_name, "LogicalResourceId": old_b},
                "Destination": {"StackName": stack_name, "LogicalResourceId": new_b},
            },
        ],
    )["StackRefactorId"]
    status = _wait_refactor_status(cfn, refactor_id, {"CREATE_COMPLETE", "CREATE_FAILED"})
    assert status == "CREATE_COMPLETE", f"stack refactor {refactor_id!r} ended {status!r} before listing actions"

    whole = cfn.list_stack_refactor_actions(StackRefactorId=refactor_id)
    assert "NextToken" not in whole, (
        f"expected the unpaginated call to fit on one page, got a NextToken {whole.get('NextToken')!r}"
    )
    whole_keys = sorted(_action_key(a) for a in whole["StackRefactorActions"])
    assert len(whole_keys) >= 2, f"expected at least 2 actions (one per renamed resource), got {whole_keys!r}"

    paged_keys: list = []
    seen_tokens: set = set()
    kwargs = {"StackRefactorId": refactor_id, "MaxResults": 1}
    while True:
        page = cfn.list_stack_refactor_actions(**kwargs)
        actions = page["StackRefactorActions"]
        assert len(actions) <= 1, f"MaxResults=1 returned {len(actions)} actions on one page: {actions!r}"
        paged_keys.extend(_action_key(a) for a in actions)
        token = page.get("NextToken")
        if not token:
            break
        assert token not in seen_tokens, f"NextToken {token!r} repeated; pagination looped"
        seen_tokens.add(token)
        kwargs["NextToken"] = token

    assert sorted(paged_keys) == whole_keys, (
        f"MaxResults=1 pagination collected {sorted(paged_keys)!r}, expected exactly {whole_keys!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
