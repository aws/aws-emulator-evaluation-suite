"""stack-rollback-stack-role-arn-unassumable-role-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-rollback-stack-role-arn-unassumable-role-rejected"
GROUP = "stack-rollback"
SERVICES = ["cloudformation", "iam"]


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RollbackStack with a RoleARN CloudFormation may not assume is refused and the stack stays
    UPDATE_FAILED; with the stack's own service role the identical call rolls it back.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RollbackStack.html"""
    cfn, iam = ctx.client("cloudformation"), ctx.client("iam")
    # Created first, so it has propagated at least as long as the good role when it is used.
    wrong = _role(ctx, iam, "lambda.amazonaws.com")
    good = _role(ctx, iam, "cloudformation.amazonaws.com")
    stack_id = _create(ctx, cfn, ctx.unique_name("sim2real-cfn-rbrole-"), _template(fail=False))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"

    # The first use of the new role waits out IAM propagation on its documented refusal.
    _poll(lambda: _accepted(lambda: cfn.update_stack(StackName=stack_id, TemplateBody=_template(fail=True),
                                                     RoleARN=good, DisableRollback=True), good),
          bool, timeout_s=_cap(ctx, 120.0), interval_s=5.0, what="the service role became assumable")
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_FAILED", f"the failing update ended {_stack(cfn, stack_id)!r}"
    assert _stack(cfn, stack_id)["RoleARN"] == good, f"RoleARN after the update: {_stack(cfn, stack_id).get('RoleARN')!r}"

    got = _error(lambda: cfn.rollback_stack(StackName=stack_id, RoleARN=wrong))
    assert got == ("ValidationError", f"Role {wrong} is invalid or cannot be assumed"), f"RollbackStack with {wrong!r}: {got!r}"
    assert _stack(cfn, stack_id)["StackStatus"] == "UPDATE_FAILED", f"the refusal moved the stack: {_stack(cfn, stack_id)!r}"
    assert _stack(cfn, stack_id)["RoleARN"] == good, f"the refusal changed RoleARN: {_stack(cfn, stack_id).get('RoleARN')!r}"

    cfn.rollback_stack(StackName=stack_id, RoleARN=good)
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_COMPLETE", f"rollback ended {_stack(cfn, stack_id)!r}"
    kept = [r["LogicalResourceId"] for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]]
    assert kept == ["Handle"], f"resources after the rollback: {kept!r}"


def _accepted(call, role: str) -> bool:
    """True once ``call`` succeeds; False while it is refused only because ``role`` has not propagated."""
    try:
        call()
    except ClientError as exc:
        if (exc.response["Error"]["Code"], exc.response["Error"].get("Message")) == (
                "ValidationError", f"Role {role} is invalid or cannot be assumed"):
            return False
        raise
    return True


def _role(ctx, iam, service: str) -> str:
    """A role trusting ``service`` with an inline policy for stack operations; deleted at cleanup."""
    name = ctx.unique_name("sim2real-cfn-rbrole-")
    arn = iam.create_role(RoleName=name, Tags=_TAGS, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.put_role_policy(RoleName=name, PolicyName="stack", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "cloudformation:*", "Resource": "*"}]}))
    return arn


def _delete_role(iam, name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=name, PolicyName="stack")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _template(*, fail: bool) -> str:
    res: dict = {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}
    if fail:
        res["Fast"] = {"Type": "AWS::CloudFormation::WaitCondition",
                       "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "1", "Count": 1}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": res})


# ===== helpers =====

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: A stack transition here takes seconds to a few minutes; the bound only stops a hung poll.
_DEADLINE_S = 600.0


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll(probe, done, *, timeout_s: float = _DEADLINE_S, interval_s: float = 3.0, what: str = "condition"):
    """Call ``probe()`` until ``done(result)`` holds and return the result; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(cfn, stack_id: str, timeout_s: float = _DEADLINE_S) -> str:
    """The stack's status once no operation is in progress on it."""
    return _poll(lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=timeout_s, what=f"stack {stack_id} settled")


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE by id; DELETE_FAILED or a timeout raises."""
    status = _stack(cfn, stack_id)["StackStatus"]
    if status == "UPDATE_IN_PROGRESS":
        cfn.cancel_update_stack(StackName=stack_id)
    if status != "CREATE_IN_PROGRESS":
        status = _settle(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _stack(cfn, stack_id)["StackStatus"],
                  lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}")


def _create(ctx, cfn, name: str, body: str, **kw) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(StackName=name, TemplateBody=body, Tags=_TAGS, **kw)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
