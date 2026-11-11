"""cfn-resource-import-wrong-identifier-key-rejected-before-change-set-exists."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-resource-import-wrong-identifier-key-rejected-before-change-set-exists"

GROUP = "deploy_import"

SERVICES = ["cloudformation", "sqs"]

_WRONG_IDENTIFIER_KEY = (
    "ValidationError",
    "Invalid resource identifier for resource type AWS::SQS::Queue. Expected [QueueUrl]",
)


def _stack_absent(name: str) -> tuple[str, str]:
    """The exact refusal DescribeStacks returns for a stack name that does not exist."""
    return ("ValidationError", f"Stack with id {name} does not exist")


def _template(queue_name: str) -> str:
    """A minimal IMPORT template; DeletionPolicy Retain is required by the IMPORT change set."""
    return json.dumps({
        "Resources": {
            "Imported": {
                "Type": "AWS::SQS::Queue",
                "DeletionPolicy": "Retain",
                "Properties": {"QueueName": queue_name},
            },
        },
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChangeSet for an IMPORT rejects a ResourcesToImport identifier keyed by the wrong
    name (QueueURL instead of QueueUrl) with ValidationError before any stack exists, while the
    same import keyed correctly succeeds and creates one.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    queue_name = _xname(ctx, "imp-badkey")
    queue_url = sqs.create_queue(QueueName=queue_name,
                                 tags={"sim2real": "cfn-resource-import-badkey"})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_by_name_if_present(sqs, queue_name))

    bad_stack = _xname(ctx, "imp-badkey-s")
    expect_error(lambda: cfn.create_change_set(
        StackName=bad_stack,
        ChangeSetName=_xname(ctx, "imp-badkey-cs"),
        ChangeSetType="IMPORT",
        TemplateBody=_template(queue_name),
        ResourcesToImport=[{
            "ResourceType": "AWS::SQS::Queue",
            "LogicalResourceId": "Imported",
            # The wrong key for this resource type: CloudFormation names SQS queues by QueueUrl,
            # not QueueURL.
            "ResourceIdentifier": {"QueueURL": queue_url},
        }],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    ), *_WRONG_IDENTIFIER_KEY)

    # The refusal is synchronous and precedes any stack: nothing was created to clean up.
    expect_error(lambda: cfn.describe_stacks(StackName=bad_stack), *_stack_absent(bad_stack))

    # Positive control: the identical import, keyed correctly, succeeds and does create a stack.
    good_stack = _xname(ctx, "imp-goodkey-s")
    change_set = cfn.create_change_set(
        StackName=good_stack,
        ChangeSetName=_xname(ctx, "imp-goodkey-cs"),
        ChangeSetType="IMPORT",
        TemplateBody=_template(queue_name),
        ResourcesToImport=[{
            "ResourceType": "AWS::SQS::Queue",
            "LogicalResourceId": "Imported",
            "ResourceIdentifier": {"QueueUrl": queue_url},
        }],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )["Id"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, good_stack, timeout_s=300.0))

    cs_status = _poll_until(lambda: _change_set(cfn, change_set)["Status"],
                            lambda s: s in {"CREATE_COMPLETE", "FAILED"},
                            timeout_s=300.0, interval_s=3.0,
                            description=f"IMPORT change set for {good_stack}")
    described = _change_set(cfn, change_set)
    assert cs_status == "CREATE_COMPLETE", (
        f"the correctly keyed IMPORT change set must succeed, got {cs_status!r}: "
        f"{described.get('StatusReason')!r}"
    )
    assert describe_stack_status(cfn, good_stack) == "REVIEW_IN_PROGRESS", (
        f"a successfully created IMPORT change set must leave its stack REVIEW_IN_PROGRESS, "
        f"got {describe_stack_status(cfn, good_stack)!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _queue_url_or_none(sqs, name: str) -> str | None:
    try:
        return sqs.get_queue_url(QueueName=name)["QueueUrl"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == _NO_SUCH_QUEUE:
            return None
        raise


def _delete_queue_by_name_if_present(sqs, name: str) -> None:
    """Best-effort queue teardown by name; already-deleted is not an error."""
    url = _queue_url_or_none(sqs, name)
    if url:
        sqs.delete_queue(QueueUrl=url)


def describe_stack_status(cfn, name: str) -> str:
    """The stack's status, or "GONE" when DescribeStacks reports exactly that it does not exist."""
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == _stack_absent(name):
            return "GONE"
        raise


def _change_set(cfn, change_set_id: str) -> dict[str, Any]:
    """DescribeChangeSet with its Changes paginated in."""
    out: dict[str, Any] = {}
    changes: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"ChangeSetName": change_set_id}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_change_set(**kwargs)
        out = page
        changes.extend(page.get("Changes", []))
        token = page.get("NextToken")
        if not token:
            break
    out["Changes"] = changes
    return out


def _delete_stack_and_wait(ctx, name: str, *, timeout_s=900.0) -> None:
    """Delete a stack and wait for it to go; DELETE_FAILED or a timeout raises."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=name)
    final = _poll_until(lambda: describe_stack_status(cfn, name),
                        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
                        timeout_s=timeout_s, interval_s=5.0,
                        description=f"delete stack {name}")
    if final == "DELETE_FAILED":
        raise RuntimeError(f"stack {name} ended DELETE_FAILED; its resources are stranded")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
