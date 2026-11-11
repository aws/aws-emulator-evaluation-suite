"""rollback-stack-physically-deletes-the-preserved-resource."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rollback-stack-physically-deletes-the-preserved-resource"
GROUP = "rollback"
SERVICES = ["cloudformation"]

#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0
_NOT_FOUND = "ParameterNotFound"


# timing:real-time — workflow: 60 s https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-creationpolicy.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """DisableRollback parks a failed create with its earlier resource still physically alive, and
    a later RollbackStack must actually delete that resource at its own service."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    tag = [{"Key": "sim2real-check", "Value": CHECK}]

    stack = ctx.unique_name("sim2real-cfn-rbstack-")
    keep_name = "/" + ctx.unique_name("sim2real-cfn-rbstack-keep-")
    keep_value = ctx.unique_name("kept-")

    stack_id = cfn.create_stack(
        StackName=stack,
        TemplateBody=_template(keep_name, keep_value),
        DisableRollback=True,
        Tags=tag,
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    # If the target is broken and leaves the parameter behind, nothing else should have to.
    ctx.on_cleanup(lambda: _delete_parameter_if_present(ssm, keep_name))

    # --- Beat 1: the stack parks at CREATE_FAILED, it does not roll back -------------------------
    parked = _poll_status(
        cfn,
        stack,
        {"CREATE_FAILED", "CREATE_COMPLETE", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        why="the PT1M ResourceSignal timeout must fail the second resource",
    )
    assert parked == "CREATE_FAILED", (
        f"CreateStack(DisableRollback=True) must park the failed create in CREATE_FAILED, got "
        f"{parked!r}; ROLLBACK_COMPLETE here means DisableRollback was ignored"
    )

    # The earlier resource genuinely reached CREATE_COMPLETE, so the beats below are about its
    # deletion and not about it never having existed.
    assert _reached_create_complete(cfn, stack, "Keep"), (
        f"stack {stack!r} has no CREATE_COMPLETE event for logical id 'Keep'; the check would then "
        "be asserting the absence of something never created"
    )

    # --- Beat 2: positive control on the same wiring — the resource IS there ---------------------
    # This is what bounds the absence asserted in beat 4: a target where GetParameter always 404s
    # fails here rather than scoring green there.
    present = ssm.get_parameter(Name=keep_name)["Parameter"]["Value"]
    assert present == keep_value, (
        f"parameter {keep_name!r}: expected the preserved value {keep_value!r} while the stack sits "
        f"in CREATE_FAILED with DisableRollback=True, got {present!r}"
    )

    # --- Beat 3: RollbackStack drives the stack to ROLLBACK_COMPLETE -----------------------------
    cfn.rollback_stack(StackName=stack)
    rolled = _poll_status(
        cfn,
        stack,
        {"ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        why="RollbackStack must reach a rollback terminal",
    )
    assert rolled == "ROLLBACK_COMPLETE", (
        f"RollbackStack on a CREATE_FAILED stack must reach ROLLBACK_COMPLETE, got {rolled!r} "
        f"(reason={_status_reason(cfn, stack)!r})"
    )

    # --- Beat 4: the terminal read — the resource is GONE at its own service ---------------------
    # A different operation, at a different service, than the one that mutated.
    # DescribeStackResources reporting DELETE_COMPLETE is a status word a target can print
    # without deleting anything.
    # AWS answers ParameterNotFound 400 with an empty message.
    refused = _expect_error(lambda: ssm.get_parameter(Name=keep_name), (_NOT_FOUND,), require_message=False)
    assert refused.response["Error"].get("Message", "") == "", refused.response["Error"]

    # --- Beat 4b: the parameter is unlisted at SSM -----------------------------------------------
    listed = [
        p["Name"]
        for page in ssm.get_paginator("describe_parameters").paginate(
            ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [keep_name]}])
        for p in page.get("Parameters", [])
    ]
    assert listed == [], f"after ROLLBACK_COMPLETE, DescribeParameters still lists {listed!r}"

    # --- Beat 5: a MUTATION on the dead resource also fails ---------------------------------
    refused = _expect_error(lambda: ssm.delete_parameter(Name=keep_name), (_NOT_FOUND,), require_message=False)
    assert refused.response["Error"].get("Message", "") == "", refused.response["Error"]

    # --- Beat 6: the ROLLBACK_COMPLETE stack itself is deleted and gone --------------------------
    cfn.delete_stack(StackName=stack)
    _poll_gone(cfn, stack_id)
    _assert_stack_gone(cfn, stack)


# ===== helpers =====


def _template(keep_name: str, keep_value: str) -> str:
    """One resource that must succeed, then one that must fail, ordered by DependsOn.

    The failure is a CreationPolicy.ResourceSignal that nothing will ever satisfy: it is
    CloudFormation-native (no second service needed to manufacture it), deterministic, and bounded
    by the PT1M timeout. DependsOn pins the ordering so 'Keep' is genuinely created BEFORE the
    failure — without it CloudFormation may create both concurrently and there is no
    already-created resource whose fate DisableRollback/RollbackStack decides.
    """
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Keep": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": keep_name, "Type": "String", "Value": keep_value},
                },
                "Doomed": {
                    "Type": "AWS::CloudFormation::WaitCondition",
                    "DependsOn": "Keep",
                    "CreationPolicy": {"ResourceSignal": {"Timeout": "PT1M", "Count": 1}},
                },
            },
        }
    )


def _poll_status(cfn, stack_name: str, terminal: set[str], *, timeout_s: float = POLL_BUDGET_S, why: str) -> str:
    """Bounded retry with a deadline; RAISES on timeout rather than returning the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(4.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach any of {sorted(terminal)!r} within {timeout_s}s "
        f"[{why}] (last={last!r})"
    )


def _status_reason(cfn, stack_name: str) -> str:
    return cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("StackStatusReason") or ""


def _reached_create_complete(cfn, stack_name: str, logical_id: str) -> bool:
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        for event in page["StackEvents"]:
            if event.get("LogicalResourceId") == logical_id and event.get("ResourceStatus") == "CREATE_COMPLETE":
                return True
    return False


def _assert_error(exc, codes, *, status=400, contains=(), require_message=True) -> None:
    """Grade a ClientError on code, HTTP status, the exact message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    if require_message:
        assert msg.strip(), f"expected the exact message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=(), require_message=True):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains, require_message=require_message)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


_ACTIVE_STACK_STATUSES = [
    "CREATE_IN_PROGRESS", "CREATE_FAILED", "CREATE_COMPLETE", "ROLLBACK_IN_PROGRESS",
    "ROLLBACK_FAILED", "ROLLBACK_COMPLETE", "DELETE_IN_PROGRESS", "DELETE_FAILED",
    "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", "UPDATE_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_FAILED",
    "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS", "UPDATE_ROLLBACK_COMPLETE",
    "REVIEW_IN_PROGRESS", "IMPORT_IN_PROGRESS", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_IN_PROGRESS", "IMPORT_ROLLBACK_FAILED", "IMPORT_ROLLBACK_COMPLETE",
]


def _assert_stack_gone(cf, name):
    """The three gone beats for a deleted stack: not found by name, unlisted, not updatable."""
    # AWS: DescribeStacks by name of a deleted stack is ValidationError 400 "Stack with id <name>
    # does not exist" (polled: by-name lookup converges once DELETE_COMPLETE is reached).
    refused = _poll_refused(lambda: cf.describe_stacks(StackName=name), ("ValidationError",))
    expected_message = f"Stack with id {name} does not exist"
    assert refused.response["Error"]["Message"] == expected_message, (
        f"expected the message {expected_message!r}, got {refused.response['Error']['Message']!r}"
    )
    # ListStacks keeps DELETE_COMPLETE summaries for 90 days, so only the active statuses are asked for.
    listed = [s["StackName"] for page in cf.get_paginator("list_stacks").paginate(
        StackStatusFilter=_ACTIVE_STACK_STATUSES) for s in page.get("StackSummaries", [])]
    assert name not in listed, f"deleted stack {name} still listed among active stacks"
    # AWS: UpdateStack(TemplateBody=...) on a missing stack is ValidationError "Stack [<name>] does not exist".
    refused = _expect_error(
        lambda: cf.update_stack(StackName=name, TemplateBody=_DEAD_STACK_TEMPLATE), ("ValidationError",)
    )
    expected_message = f"Stack [{name}] does not exist"
    assert refused.response["Error"]["Message"] == expected_message, (
        f"expected the message {expected_message!r}, got {refused.response['Error']['Message']!r}"
    )


_DEAD_STACK_TEMPLATE = '{"Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}}'


def _poll_refused(fn, codes, *, status=400, contains=()):
    """Repeat fn() until it is refused (bounded convergence), then grade the refusal."""
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        try:
            result = fn()
        except ClientError as exc:
            _assert_error(exc, codes, status=status, contains=contains)
            return exc
        if time.monotonic() > deadline:
            raise AssertionError(f"expected {codes!r} within {POLL_BUDGET_S}s, still accepted: {result!r}")
        time.sleep(5)


def _poll_gone(cfn, stack_id: str) -> None:
    """Poll DescribeStacks by StackId until DELETE_COMPLETE or DELETE_FAILED and require DELETE_COMPLETE."""
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in ("DELETE_COMPLETE", "DELETE_FAILED") or time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    assert status == "DELETE_COMPLETE", f"DeleteStack of {stack_id!r} ended {status!r}"


def _delete_parameter_if_present(ssm, name: str) -> None:
    """Teardown only: remove a parameter the target failed to delete. Scoped to this check's own
    resource, never a prefix sweep."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != _NOT_FOUND:
            raise


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
