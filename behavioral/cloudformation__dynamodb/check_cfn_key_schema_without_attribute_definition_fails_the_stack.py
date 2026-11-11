"""cfn-key-schema-without-attribute-definition-fails-the-stack."""
# A template whose KeySchema names an attribute missing from AttributeDefinitions must fail the stack and
# create no table.
#
# A direct create_table and a template are different code paths -- CloudFormation can parse a template
# and then discard part of it, which a direct create never does. A negative held only on the direct path
# says nothing about the template path.
#
# The control matters more than usual: it differs from the negative by ONE LINE of the template -- whether
# `sk` appears in AttributeDefinitions -- so passing the pair cannot be done by refusing DynamoDB
# templates generally, which is the cheap way to satisfy a lone negative.
#
# MEASURED: the failure reason states the RULE rather than naming the attribute -- "An attribute
# referenced in a KeySchema element is not defined in AttributeDefinitions" -- and carries
# HandlerErrorCode: InvalidRequest. It is a RESOURCE-handler failure, so the reason sits on the
# resource's CREATE_FAILED event.
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-key-schema-without-attribute-definition-fails-the-stack"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]

STACK_TIMEOUT_S = 600.0
_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
NOT_FOUND = "ResourceNotFoundException"


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A template whose KeySchema names an attribute missing from AttributeDefinitions fails the stack
    and creates no DynamoDB table, while the same template with that attribute declared succeeds.
    """
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")

    # --- Beat 1: positive control -- the same shape, with sk properly declared --------------------
    # First, so a later failure cannot be mistaken for "this target refuses DynamoDB templates".
    good_table = ctx.unique_name("sim2real-xsvc-keyok-")
    good_stack = ctx.unique_name("sim2real-xsvc-keyokstk-")
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(declare_sk=True),
        Parameters=[{"ParameterKey": "TableName", "ParameterValue": good_table}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    good_status = _poll_stack(cfn, good_stack)
    assert good_status == "CREATE_COMPLETE", (
        f"the control template declares every key attribute and must deploy; got {good_status!r}"
    )
    control_keys = {
        k["AttributeName"]: k["KeyType"]
        for k in ddb.describe_table(TableName=good_table)["Table"]["KeySchema"]
    }
    assert control_keys == {"pk": "HASH", "sk": "RANGE"}, (
        f"the control table must carry both key attributes, got {control_keys!r}"
    )

    # --- Beat 2: the negative -- sk in KeySchema, absent from AttributeDefinitions -----------------
    bad_table = ctx.unique_name("sim2real-xsvc-keybad-")
    bad_stack = ctx.unique_name("sim2real-xsvc-keybadstk-")
    created = cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(declare_sk=False),
        Parameters=[{"ParameterKey": "TableName", "ParameterValue": bad_table}],
    )
    # A rolled-back stack still EXISTS and needs teardown; registered before the first assertion that
    # could abandon it.
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))
    assert created.get("StackId"), (
        f"CreateStack must return a StackId even for a template that will fail; got {created!r}"
    )

    bad_status = _poll_stack(cfn, bad_stack)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a KeySchema naming an attribute absent from AttributeDefinitions must fail the stack; got "
        f"{bad_status!r}. A target that builds the broken table verbatim reaches CREATE_COMPLETE"
    )
    # On AWS the reason does NOT name the offending attribute. It states the
    # rule -- "An attribute referenced in a KeySchema element is not defined in AttributeDefinitions" --
    # and carries HandlerErrorCode: InvalidRequest. Note this is a RESOURCE-handler failure
    # (CREATE_FAILED on the resource), unlike a resource-schema refusal, whose reason sits on the
    # STACK's own event while the resource never starts.
    reason = _failure_reasons(cfn, bad_stack)
    assert "not defined in AttributeDefinitions" in reason, (
        f"the failure must state the rule it enforced; got {reason!r}. Any other cause -- a throttle, "
        f"a quota, a permission -- also reaches ROLLBACK_COMPLETE"
    )
    assert "InvalidRequest" in reason, (
        f"the resource handler must classify this as InvalidRequest; got {reason!r}"
    )

    # --- Beat 3: effect-absent -- the broken table was never built --------------------------------
    # The actual failure mode: not that the stack succeeded, but that the table existed.
    error = _client_error(lambda: ddb.describe_table(TableName=bad_table))
    assert error.get("Code") == NOT_FOUND, (
        f"the failed stack must have left no table named {bad_table!r}; describe_table gave "
        f"{error.get('Code')!r}: {error.get('Message')!r}"
    )
    assert error.get("Message") == f"Requested resource not found: Table: {bad_table} not found", (
        f"DescribeTable {NOT_FOUND} message: {error.get('Message')!r}"
    )


# ===== helpers =====


def _template(*, declare_sk: bool) -> str:
    """One table keyed on (pk, sk). `declare_sk` is the ONLY difference between the control and the
    negative: with it False, `sk` is a range key that AttributeDefinitions never declares."""
    attributes = [{"AttributeName": "pk", "AttributeType": "S"}]
    if declare_sk:
        attributes.append({"AttributeName": "sk", "AttributeType": "S"})
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"TableName": {"Type": "String"}},
            "Resources": {
                "Table": {
                    "Type": "AWS::DynamoDB::Table",
                    "Properties": {
                        "TableName": {"Ref": "TableName"},
                        "BillingMode": "PAY_PER_REQUEST",
                        "AttributeDefinitions": attributes,
                        "KeySchema": [
                            {"AttributeName": "pk", "KeyType": "HASH"},
                            {"AttributeName": "sk", "KeyType": "RANGE"},
                        ],
                    },
                }
            },
        }
    )


def _poll_stack(cfn, stack_name: str) -> str:
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _CREATE_TERMINAL:
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach a create-terminal state within {STACK_TIMEOUT_S}s "
        f"(last={last!r})"
    )


def _failure_reasons(cfn, stack_name: str) -> str:
    """Every stated reason in the stack's event history, joined.

    All events are collected rather than one: a template-validation failure and a resource-handler
    failure put their reason on different events, and which one fires here is exactly what is under
    test.
    """
    reasons = [
        event["ResourceStatusReason"]
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name)
        for event in page["StackEvents"]
        if event.get("ResourceStatusReason")
    ]
    assert reasons, (
        f"stack {stack_name!r} failed but stated no reason anywhere in its events; a failure with no "
        f"cause is not a gradable refusal"
    )
    return " | ".join(reasons)


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    ACCEPTING a request real AWS refuses is the strongest signal available and must not be reported
    as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _delete_stack(cfn, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
