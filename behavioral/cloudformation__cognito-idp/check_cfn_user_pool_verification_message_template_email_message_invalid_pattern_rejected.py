"""cfn-user-pool-verification-message-template-email-message-invalid-pattern-rejected."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-user-pool-verification-message-template-email-message-invalid-pattern-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-idp"]

_EMAIL_MESSAGE_PATTERN = r"[\p{L}\p{M}\p{S}\p{N}\p{P}\s*]*\{####\}[\p{L}\p{M}\p{S}\p{N}\p{P}\s*]*"


_CREATE_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
    }
)
_DELETE_TERMINAL = frozenset({"DELETE_COMPLETE", "DELETE_FAILED"})


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=3.0, description="condition"):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _stack_status(cfn, stack_id: str) -> str:
    """The stack's status read by StackId; the exact not-found pair reads as DELETE_COMPLETE."""
    try:
        return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
            "ValidationError",
            f"Stack with id {stack_id} does not exist",
        ):
            return "DELETE_COMPLETE"
        raise


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack whatever state it is in, and raise unless it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    status = _poll_until(
        ctx,
        lambda: _stack_status(cfn, stack_id),
        lambda s: s in _DELETE_TERMINAL,
        timeout_s=450.0,
        description=f"delete stack {stack_id}",
    )
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {status!r}, not DELETE_COMPLETE")


def _create(ctx, cfn, stack_name: str, body: str) -> tuple[str, str]:
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=body, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack_id))
    status = _poll_until(
        ctx,
        lambda: _stack_status(cfn, stack_id),
        lambda s: s in _CREATE_TERMINAL,
        timeout_s=450.0,
        description=f"stack {stack_name} creation",
    )
    return stack_id, status


def _create_failed_reason(cfn, stack_id: str, logical_id: str) -> str:
    """The ResourceStatusReason of ``logical_id``'s single CREATE_FAILED event, across all pages."""
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    reasons = [
        e.get("ResourceStatusReason", "")
        for page in pages
        for e in page["StackEvents"]
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(reasons) == 1, f"expected one CREATE_FAILED event for {logical_id}, got {reasons!r}"
    return reasons[0]


def _assert_invalid_email_message_reason(reason: str, email_value: str) -> None:
    """The reason carries the exact validation message and HandlerErrorCode, stripped of the
    two per-request ids CloudFormation and the service mint for this call."""
    inner = (
        f"1 validation error detected: Value '{email_value}' at "
        "'verificationMessageTemplate.emailMessage' failed to satisfy constraint: "
        f"Member must satisfy regular expression pattern: {_EMAIL_MESSAGE_PATTERN}"
    )
    pattern = (
        r'^Resource handler returned message: "'
        + re.escape(inner)
        + r" \(Service: CognitoIdentityProvider, Status Code: 400, Request ID: "
        r'[0-9a-f-]{36}\) \(SDK Attempt Count: \d+\)" '
        r"\(RequestToken: [0-9a-f-]{36}, HandlerErrorCode: InvalidRequest\)$"
    )
    assert re.fullmatch(pattern, reason), (
        f"resource status reason did not match the expected validation failure shape: {reason!r}"
    )


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::Cognito::UserPool whose VerificationMessageTemplate.EmailMessage
    lacks the required {####} placeholder rolls back with the service's exact validation
    error, while the same property holding a placeholder deploys and round-trips.
    """
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")
    bad_stack_name = ctx.unique_name("sim2real-behav-cogvmtbad-")
    bad_pool_name = ctx.unique_name("sim2real-behav-cogvmtbadpool-")
    bad_email_message = "Your verification code is ready."

    bad_template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Pool": {
                    "Type": "AWS::Cognito::UserPool",
                    "Properties": {
                        "UserPoolName": bad_pool_name,
                        "AutoVerifiedAttributes": ["email"],
                        "VerificationMessageTemplate": {
                            "DefaultEmailOption": "CONFIRM_WITH_CODE",
                            "EmailMessage": bad_email_message,
                        },
                    },
                },
            },
        }
    )
    bad_stack_id, status = _create(ctx, cfn, bad_stack_name, bad_template_body)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"
    reason = _create_failed_reason(cfn, bad_stack_id, "Pool")
    _assert_invalid_email_message_reason(reason, bad_email_message)

    good_stack_name = ctx.unique_name("sim2real-behav-cogvmtgood-")
    good_pool_name = ctx.unique_name("sim2real-behav-cogvmtgoodpool-")
    good_email_message = "Your verification code is {####}."

    good_template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Pool": {
                    "Type": "AWS::Cognito::UserPool",
                    "Properties": {
                        "UserPoolName": good_pool_name,
                        "AutoVerifiedAttributes": ["email"],
                        "VerificationMessageTemplate": {
                            "DefaultEmailOption": "CONFIRM_WITH_CODE",
                            "EmailMessage": good_email_message,
                        },
                    },
                },
            },
            "Outputs": {"PoolRef": {"Value": {"Ref": "Pool"}}},
        }
    )
    good_stack_id, good_status = _create(ctx, cfn, good_stack_name, good_template_body)
    assert good_status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {good_status!r}"
    stacks = cfn.describe_stacks(StackName=good_stack_id)["Stacks"]
    good_pool_id = {o["OutputKey"]: o["OutputValue"] for o in stacks[0]["Outputs"]}["PoolRef"]
    good_pool = cognito.describe_user_pool(UserPoolId=good_pool_id)["UserPool"]
    stored_message = good_pool["VerificationMessageTemplate"]["EmailMessage"]
    assert stored_message == good_email_message, (
        f"expected EmailMessage {good_email_message!r}, got {stored_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
