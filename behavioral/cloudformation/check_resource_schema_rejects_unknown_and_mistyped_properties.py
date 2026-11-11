"""resource-schema-rejects-unknown-and-mistyped-properties."""
# Resource-schema validation is asynchronous: CreateStack accepts a bad property and returns a
# StackId, then the stack goes CREATE_FAILED -> ROLLBACK_COMPLETE with a generic reason.
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-schema-rejects-unknown-and-mistyped-properties"
GROUP = "template_validation"
SERVICES = ["cloudformation"]

STACK_TIMEOUT_S = 300.0
ABSENCE_TIMEOUT_S = 120.0
TEMPLATE_TIMEOUT = 45
NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"
# Exactly one property is wrong in each negative body, hence "1 error(s)".
SCHEMA_FAILURE_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
    "with resource and property details, resolve each error, then retry the operation."
)

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An unknown property and a non-coercible value on a real AWS::SQS::Queue each fail the stack to
    ROLLBACK_COMPLETE and create no queue, while a quoted integer for the same property is coerced and
    succeeds, and ValidateTemplate accepts all three bodies.
    """
    cf = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    # Integer 45 and the string "45" must both provision; without the quoted control, refusing every
    # string-valued numeric property would pass the non-coercible case for the wrong reason.
    int_queue = ctx.unique_name("sim2real-cfn-schema-int-")
    str_queue = ctx.unique_name("sim2real-cfn-schema-str-")
    control_stack = ctx.unique_name("sim2real-cfn-schema-ctl-")
    cf.create_stack(
        StackName=control_stack,
        TemplateBody=_control_template(),
        Parameters=[
            {"ParameterKey": "IntQueueName", "ParameterValue": int_queue},
            {"ParameterKey": "StrQueueName", "ParameterValue": str_queue},
        ],
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=control_stack))
    control_status = _poll_status(cf, control_stack, why="controls")
    assert control_status == "CREATE_COMPLETE", (
        f"control stack {control_stack!r} must reach CREATE_COMPLETE, got {control_status!r}"
    )
    for label, queue_name in (("integer", int_queue), ("quoted-integer", str_queue)):
        live = _visibility_timeout(sqs, queue_name)
        assert live == str(TEMPLATE_TIMEOUT), (
            f"the {label} control queue must carry VisibilityTimeout {TEMPLATE_TIMEOUT!r}; SQS "
            f"reports {live!r}. A quoted integer is legal CloudFormation and must be coerced"
        )

    _assert_schema_failure(
        ctx, cf, sqs,
        label="unknown property",
        body=_negative_template({"VisibilityTimeout": TEMPLATE_TIMEOUT, "ThisPropertyDoesNotExist": 123}),
        stack_prefix="sim2real-cfn-schema-unk-",
        queue_prefix="sim2real-cfn-schema-unkq-",
    )

    _assert_schema_failure(
        ctx, cf, sqs,
        label="non-coercible Integer value",
        body=_negative_template({"VisibilityTimeout": "not-a-number"}),
        stack_prefix="sim2real-cfn-schema-typ-",
        queue_prefix="sim2real-cfn-schema-typq-",
    )

    # ValidateTemplate checks template structure only, so it accepts all three well-formed bodies.
    bodies = {
        "control": _control_template(),
        "unknown-property": _negative_template(
            {"VisibilityTimeout": TEMPLATE_TIMEOUT, "ThisPropertyDoesNotExist": 123}
        ),
        "mistyped-property": _negative_template({"VisibilityTimeout": "not-a-number"}),
    }
    for label, body in bodies.items():
        validated = cf.validate_template(TemplateBody=body)
        assert isinstance(validated.get("Parameters"), list), (
            f"ValidateTemplate must ACCEPT the {label} body -- it parses; only the resource schema is "
            f"violated -- got {validated!r}"
        )


def _control_template() -> str:
    """Two queues whose VisibilityTimeout is the Integer 45 and the string "45"; both are legal."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"IntQueueName": {"Type": "String"}, "StrQueueName": {"Type": "String"}},
            "Resources": {
                "IntQ": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": {"Ref": "IntQueueName"},
                        "VisibilityTimeout": TEMPLATE_TIMEOUT,
                    },
                },
                "StrQ": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": {"Ref": "StrQueueName"},
                        "VisibilityTimeout": str(TEMPLATE_TIMEOUT),
                    },
                },
            },
        }
    )


def _negative_template(queue_properties: dict) -> str:
    """One queue whose Properties are exactly what the caller passes."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"QueueName": {"Type": "String"}},
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"QueueName": {"Ref": "QueueName"}, **queue_properties},
                }
            },
        }
    )


def _assert_schema_failure(ctx, cf, sqs, *, label: str, body: str, stack_prefix: str,
                           queue_prefix: str) -> None:
    """CreateStack is accepted, the stack rolls back with the schema failure reason, and no queue
    exists."""
    queue_name = ctx.unique_name(queue_prefix)
    stack_name = ctx.unique_name(stack_prefix)

    # A rolled-back stack still exists (ROLLBACK_COMPLETE), so it needs its own teardown.
    created = cf.create_stack(
        StackName=stack_name,
        TemplateBody=body,
        Parameters=[{"ParameterKey": "QueueName", "ParameterValue": queue_name}],
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack_name))
    assert created.get("StackId"), (
        f"[{label}] CloudFormation validates the resource schema ASYNCHRONOUSLY, so CreateStack must "
        f"return a StackId rather than refusing; got {created!r}"
    )

    status = _poll_status(cf, stack_name, why=label)
    assert status == "ROLLBACK_COMPLETE", (
        f"[{label}] the stack must fail its resource-schema validation and roll back, got {status!r}"
    )

    reason = _stack_failure_reason(cf, stack_name)
    assert reason == SCHEMA_FAILURE_REASON, (
        f"[{label}] the CREATE_FAILED reason must report a resource-schema validation failure "
        f"({SCHEMA_FAILURE_REASON!r}), got {reason!r}. A rollback for any other cause -- a throttle, a "
        f"quota, a missing permission -- would also reach ROLLBACK_COMPLETE"
    )

    _assert_queue_absent(sqs, queue_name)


def _visibility_timeout(sqs, queue_name: str) -> str:
    url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]["VisibilityTimeout"]


def _poll_status(cf, stack_name: str, *, why: str) -> str:
    """Poll until a create-terminal status; raise on timeout."""
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _CREATE_TERMINAL:
            return last
        time.sleep(4.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach a create-terminal state within {STACK_TIMEOUT_S}s "
        f"[{why}] (last={last!r})"
    )


def _stack_failure_reason(cf, stack_name: str) -> str:
    """Reasons on CREATE_FAILED events; a schema failure is reported against the stack itself, and
    pagination matters because the reason is older than the rollback's own events."""
    reasons = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        for event in page["StackEvents"]:
            if event["ResourceStatus"] == "CREATE_FAILED" and event.get("ResourceStatusReason"):
                reasons.append(event["ResourceStatusReason"])
    assert reasons, (
        f"stack {stack_name!r} rolled back but emitted no CREATE_FAILED event carrying a reason; a "
        f"rollback with no stated cause is not a gradable refusal"
    )
    return " | ".join(reasons)


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _assert_queue_absent(sqs, queue_name: str) -> None:
    """Assert absence by GetQueueUrl and by a fully paginated ListQueues, which may hold other
    queues beyond page one."""
    error = _client_error(lambda: sqs.get_queue_url(QueueName=queue_name))
    assert error.get("Code") == NO_SUCH_QUEUE, (
        f"the rolled-back stack must have left no queue {queue_name!r}; get_queue_url gave "
        f"{error.get('Code')!r}: {error.get('Message')!r}"
    )
    assert error.get("Message") == "The specified queue does not exist.", error
    deadline = time.monotonic() + ABSENCE_TIMEOUT_S
    while True:
        names: set[str] = set()
        for page in sqs.get_paginator("list_queues").paginate():
            for url in page.get("QueueUrls", []) or []:
                names.add(url.rsplit("/", 1)[-1])
        if queue_name not in names:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"queue {queue_name!r} is still listed {ABSENCE_TIMEOUT_S}s after the stack that "
                f"declared it rolled back -- the rollback did not remove it"
            )
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
