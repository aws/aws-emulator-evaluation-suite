"""stack-refactor-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-refactor-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A stack refactor plan progresses from creation through planned actions to
    execution and is describable/listable throughout."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")

    if not hasattr(cfn, "create_stack_refactor"):
        raise AssertionError("unreachable: installed botocore does not support CreateStackRefactor")

    stack_name = ctx.unique_name("sim2real-refactor-")
    old_template = json.dumps(
        {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"OldTopic": {"Type": "AWS::SNS::Topic"}}}
    )
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=old_template,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))
    _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180)

    old_physical_id = _resource_physical_id(cfn, stack_name, "OldTopic")

    new_template = json.dumps(
        {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"NewTopic": {"Type": "AWS::SNS::Topic"}}}
    )

    try:
        refactor_id = cfn.create_stack_refactor(
            StackDefinitions=[{"StackName": stack_name, "TemplateBody": new_template}],
            ResourceMappings=[
                {
                    "Source": {"StackName": stack_name, "LogicalResourceId": "OldTopic"},
                    "Destination": {"StackName": stack_name, "LogicalResourceId": "NewTopic"},
                }
            ],
        )["StackRefactorId"]
    except ClientError as exc:
        raise AssertionError(f"unreachable: CreateStackRefactor not usable in this account/region ({exc.response['Error']['Code']})") from exc

    def _describe():
        return cfn.describe_stack_refactor(StackRefactorId=refactor_id)

    created = _poll_until(_describe, lambda r: r["Status"] in ("CREATE_COMPLETE", "CREATE_FAILED"), timeout_s=300, interval_s=10)
    if created["Status"] != "CREATE_COMPLETE":
        raise AssertionError(f"stack refactor plan creation failed: {created.get('StatusReason')}")

    refactors = cfn.list_stack_refactors()["StackRefactorSummaries"]
    assert any(r["StackRefactorId"] == refactor_id for r in refactors), refactors

    actions = cfn.list_stack_refactor_actions(StackRefactorId=refactor_id)["StackRefactorActions"]
    assert len(actions) >= 1, "expected at least one planned refactor action"

    cfn.execute_stack_refactor(StackRefactorId=refactor_id)

    executed = _poll_until(
        _describe,
        lambda r: r["ExecutionStatus"] in ("EXECUTE_COMPLETE", "EXECUTE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"),
        timeout_s=300,
        interval_s=10,
    )
    assert executed["ExecutionStatus"] == "EXECUTE_COMPLETE", executed

    new_physical_id = _resource_physical_id(cfn, stack_name, "NewTopic")
    assert new_physical_id == old_physical_id, "rename should retain the same physical SNS topic"

    # Independent terminal read at the SNS consumer, not the CloudFormation orchestrator:
    # the topic ARN the refactor preserved must still be a live, addressable SNS topic.
    topic_attrs = sns.get_topic_attributes(TopicArn=new_physical_id)["Attributes"]
    assert topic_attrs["TopicArn"] == new_physical_id, topic_attrs


def _safe_delete_stack(cfn, stack_name) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _resource_physical_id(cfn, stack_name, logical_id):
    return cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _wait_stack_status(cfn, stack_name, terminal_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal_statuses:
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} did not reach {terminal_statuses}, last={status}")
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last result={result}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
