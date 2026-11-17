"""cfn-esm-malformed-filter-pattern-rolls-back-queue-and-function."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-esm-malformed-filter-pattern-rolls-back-queue-and-function"
GROUP = "deploy-esm"
SERVICES = ["cloudformation", "lambda", "sqs"]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}


def _template(pattern: str) -> str:
    """A stack declaring its own queue, role, function and EventSourceMapping together, so a
    rejected mapping rolls the whole estate back."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "QueueNameParam": {"Type": "String"},
            "RoleNameParam": {"Type": "String"},
            "FunctionNameParam": {"Type": "String"},
        },
        "Resources": {
            "SourceQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "QueueNameParam"}, "VisibilityTimeout": 30},
            },
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "RoleNameParam"},
                    "AssumeRolePolicyDocument": _TRUST_POLICY,
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole",
                    ],
                },
            },
            "ConsumerFn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": {"Ref": "FunctionNameParam"},
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": (
                        "def handler(event, context):\n"
                        "    return {'processed': len(event.get('Records', []))}\n"
                    )},
                },
            },
            "Esm": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {
                    "EventSourceArn": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                    "FunctionName": {"Ref": "ConsumerFn"},
                    "BatchSize": 5,
                    "Enabled": True,
                    "FilterCriteria": {"Filters": [{"Pattern": pattern}]},
                },
            },
        },
        "Outputs": {"MappingId": {"Value": {"Ref": "Esm"}}},
    })


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _assert_malformed_filter_reason(reason: str) -> None:
    """Assert the Esm resource's CREATE_FAILED reason matches the fixed wrapper CloudFormation
    uses for this rejection, with only its two per-call ids varying."""
    prefix = (
        'Resource handler returned message: "Invalid request provided: '
        "Invalid filter pattern definition. (Service: Lambda, Status Code: 400, Request ID: "
    )
    mid = ') (SDK Attempt Count: 1)" (RequestToken: '
    suffix = ", HandlerErrorCode: InvalidRequest)"
    assert reason.startswith(prefix), f"unexpected CREATE_FAILED reason prefix: {reason!r}"
    rest = reason[len(prefix):]
    mid_at = rest.find(mid)
    assert mid_at > 0, f"unexpected CREATE_FAILED reason shape: {reason!r}"
    request_id, rest = rest[:mid_at], rest[mid_at + len(mid):]
    assert rest.endswith(suffix), f"unexpected CREATE_FAILED reason suffix: {reason!r}"
    request_token = rest[:-len(suffix)]
    uuid.UUID(request_id)
    uuid.UUID(request_token)
    rebuilt = prefix + request_id + mid + request_token + suffix
    assert rebuilt == reason, f"expected {rebuilt!r}, got {reason!r}"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack's EventSourceMapping with a non-JSON, or a non-array-valued, FilterCriteria
    pattern rolls the whole stack back, leaving the queue with no mapping and its function gone.
    The identical template with an array-valued pattern deploys and round-trips that filter.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    for label, pattern in (
        ("notjson", "{not valid json"),
        ("barestring", json.dumps({"body": {"kind": "order"}})),
    ):
        names = {
            "QueueNameParam": ctx.unique_name(f"sim2real-esm-{label}-q-"),
            "RoleNameParam": ctx.unique_name(f"sim2real-esm-{label}-role-"),
            "FunctionNameParam": ctx.unique_name(f"sim2real-esm-{label}-fn-"),
        }
        stack_name = ctx.unique_name(f"sim2real-esm-{label}-stk-")
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=_template(pattern),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in names.items()],
        )
        ctx.on_cleanup(lambda s=stack_name: _delete_stack_and_wait(cfn, s))
        status = _wait_terminal(cfn, stack_name)
        assert status == "ROLLBACK_COMPLETE", (
            f"malformed pattern ({label}): expected the stack to roll back, got {status!r}"
        )

        reason = _create_failed_reason(cfn, stack_name, "Esm")
        assert reason is not None, f"no CREATE_FAILED reason recorded for the Esm resource ({label})"
        _assert_malformed_filter_reason(reason)

        queue_arn = f"arn:aws:sqs:{ctx.region}:{ctx.account}:{names['QueueNameParam']}"
        mappings = lam.list_event_source_mappings(EventSourceArn=queue_arn)["EventSourceMappings"]
        assert mappings == [], (
            f"expected no event source mapping on the rolled-back queue ({label}), got {mappings!r}"
        )

        function_name = names["FunctionNameParam"]
        _function_gone = (
            "ResourceNotFoundException",
            f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{function_name}",
        )
        expect_error(lambda: lam.get_function(FunctionName=function_name), *_function_gone)

        queue_name = names["QueueNameParam"]
        _queue_gone = ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.")
        expect_error(lambda: sqs.get_queue_url(QueueName=queue_name), *_queue_gone)

    # --- positive control: the identical template with a well-formed array-valued pattern -----
    good_names = {
        "QueueNameParam": ctx.unique_name("sim2real-esm-good-q-"),
        "RoleNameParam": ctx.unique_name("sim2real-esm-good-role-"),
        "FunctionNameParam": ctx.unique_name("sim2real-esm-good-fn-"),
    }
    good_stack = ctx.unique_name("sim2real-esm-good-stk-")
    valid_pattern = json.dumps({"body": {"kind": ["order"]}})
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(valid_pattern),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in good_names.items()],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, good_stack))
    status = _wait_terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", (
        f"the well-formed pattern: expected CREATE_COMPLETE, got {status!r} — "
        f"the malformed runs' failure was not isolated to the pattern string"
    )

    mapping_uuid = _stack_output(cfn, good_stack, "MappingId")
    esm = _poll_until(
        lambda: lam.get_event_source_mapping(UUID=mapping_uuid),
        lambda m: m["State"] not in {"Creating", "Enabling"},
        timeout_s=180.0,
        description=f"ESM {mapping_uuid!r} to leave Creating/Enabling",
    )
    filters = esm.get("FilterCriteria", {}).get("Filters", [])
    assert filters == [{"Pattern": valid_pattern}], (
        f"expected the well-formed pattern to round-trip as the only filter, got {filters!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
}


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 300.0) -> str:
    return _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in _TERMINAL_STACK_STATUSES,
        timeout_s=timeout_s, interval_s=5.0, description=f"CFN stack {stack_name}",
    )


def _create_failed_reason(cfn, stack_name: str, logical_id: str):
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    for e in events:
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED":
            return e.get("ResourceStatusReason")
    return None


def _stack_output(cfn, stack_name: str, key: str) -> str:
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    for o in outputs:
        if o["OutputKey"] == key:
            return o["OutputValue"]
    raise AssertionError(f"stack {stack_name} has no output {key!r}: {outputs!r}")


def _delete_stack_and_wait(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in str(exc):
                return "GONE"
            raise

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=300.0,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
