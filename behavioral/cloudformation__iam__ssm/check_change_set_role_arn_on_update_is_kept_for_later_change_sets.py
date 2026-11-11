"""change-set-role-arn-on-update-is-kept-for-later-change-sets."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-role-arn-on-update-is-kept-for-later-change-sets"
GROUP = "change_sets"
SERVICES = ["cloudformation", "iam", "ssm"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
#: Real-AWS wall bound of one denied update: its rollback cleanup lingers in
#: *_CLEANUP_IN_PROGRESS for minutes. Every wait is a condition poll.
_DEADLINE_S = 900.0
#: Bound on retrying the first role update while the role's inline policy propagates.
_POLICY_RETRY_S = 120.0
_DENIED = re.compile(r"^Resource handler returned message: \"Access denied for operation "
                     r"'PutParameter'\.\" \(RequestToken: [0-9a-f-]{36}, "
                     r"HandlerErrorCode: AccessDenied\)$")
_TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"},
    "Action": "sts:AssumeRole"}]})


def _template(params):
    return json.dumps({"Resources": {
        logical: {"Type": "AWS::SSM::Parameter",
                  "Properties": {"Name": name, "Type": "String", "Value": logical}}
        for logical, name in params.items()}})


def _delete_role(iam, role, cf, stack_id):
    """Delete the stack's RoleARN role only once the stack is gone, so the stack stays deletable."""
    try:
        sid = stack_id()
    except NameError:  # the stack was never created
        sid = None
    if sid is not None:
        try:
            status = cf.describe_stacks(StackName=sid)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise
            status = "DELETE_COMPLETE"
        if status != "DELETE_COMPLETE":
            raise RuntimeError(f"stack {sid} is {status!r}; role {role} kept so the stack "
                               f"can still be deleted")
    for name in iam.list_role_policies(RoleName=role)["PolicyNames"]:
        iam.delete_role_policy(RoleName=role, PolicyName=name)
    iam.delete_role(RoleName=role)


def _error(fn):
    """(code, message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, the call succeeded: {result!r}")


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _wait_stack(cf, stack_id, *, timeout_s=300.0):
    """Poll DescribeStacks by id until the status leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)


def _wait_change_set(cf, cs_id, *, timeout_s=180.0, **extra):
    """Poll DescribeChangeSet until CREATE_COMPLETE or FAILED; return the description."""
    deadline = time.monotonic() + timeout_s
    while True:
        cs = cf.describe_change_set(ChangeSetName=cs_id, **extra)
        if cs["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return cs
        if time.monotonic() > deadline:
            raise AssertionError(f"change set still {cs['Status']!r} after {timeout_s}s")
        time.sleep(3)


def _delete_stack(cf, stack_id, *, timeout_s=600.0):
    """Delete a stack by id and poll until DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] in ("DELETE_COMPLETE", "DELETE_FAILED"):
            break
        if time.monotonic() > deadline:
            raise RuntimeError(f"stack {stack_id} still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)
    if stack["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {stack['StackStatus']!r}: "
                           f"{stack.get('StackStatusReason')!r}")


def _events(cf, stack_id):
    """Every StackEvent of the stack, oldest first."""
    out = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _create_failed_reasons(cf, stack_id, before, logical):
    """ResourceStatusReason of every CREATE_FAILED event of ``logical`` not in ``before``."""
    return [e.get("ResourceStatusReason", "") for e in _events(cf, stack_id)
            if e["EventId"] not in before
            and (e["LogicalResourceId"], e["ResourceStatus"]) == (logical, "CREATE_FAILED")]


def _change_set(ctx, cf, stack_id, params, *, wait_timeout_s=300.0, **role):
    """Create an UPDATE change set, retrying while a fresh role cannot yet be assumed."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            cs_id = cf.create_change_set(StackName=stack_id, ChangeSetType="UPDATE",
                                         TemplateBody=_template(params),
                                         ChangeSetName=ctx.unique_name("sim2real-xsvc-csrole-cs-"),
                                         **role)["Id"]
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            if "cannot be assumed" not in msg or time.monotonic() > deadline:
                raise
            time.sleep(5)  # IAM propagation of the new role's trust policy
    cs = _wait_change_set(cf, cs_id, timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs.get('StatusReason')!r}"
    cf.execute_change_set(ChangeSetName=cs_id)
    return _wait_stack(cf, stack_id, timeout_s=_cap(ctx, wait_timeout_s))


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A RoleARN given on an UPDATE change set becomes the stack's role, and a later change set that
    omits it still runs as that role: a parameter outside its policy fails with an AccessDenied.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html
    """
    cf = ctx.client("cloudformation")
    iam = ctx.client("iam")
    prefix = "/" + ctx.unique_name("sim2real-xsvc-csrole-")
    role_name = ctx.unique_name("sim2real-xsvc-csrole-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST,
                               Tags=_TAGS)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, cf, lambda: stack_id))
    partition = role_arn.split(":")[1]
    iam.put_role_policy(RoleName=role_name, PolicyName="ssm-prefix", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "ssm:*",
            "Resource": f"arn:{partition}:ssm:{ctx.region}:{ctx.account}:parameter{prefix}/*"}]}))

    inside = {"A": f"{prefix}/a"}
    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-xsvc-csrole-"), Tags=_TAGS,
                               TemplateBody=_template(inside))["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert (stack["StackStatus"], stack.get("RoleARN")) == ("CREATE_COMPLETE", None), stack

    inside["B"] = f"{prefix}/b"
    retry_until = time.monotonic() + _POLICY_RETRY_S
    while True:
        before = {e["EventId"] for e in _events(cf, stack_id)}
        stack = _change_set(ctx, cf, stack_id, inside, wait_timeout_s=_DEADLINE_S, RoleARN=role_arn)
        if stack["StackStatus"] != "UPDATE_ROLLBACK_COMPLETE" or time.monotonic() > retry_until:
            break
        denied = _create_failed_reasons(cf, stack_id, before, "B")
        if not denied or not all(_DENIED.match(r) for r in denied):
            break
        time.sleep(5)  # the inline policy is not yet effective for the role's session
    assert stack["StackStatus"] == "UPDATE_COMPLETE", f"role update: {stack['StackStatus']!r}"
    assert stack.get("RoleARN") == role_arn, f"DescribeStacks RoleARN: {stack.get('RoleARN')!r}"

    # No RoleARN on this change set: the stack's role is used, and it may not write outside prefix.
    outside = "/" + ctx.unique_name("sim2real-xsvc-csrole-out-")
    before = {e["EventId"] for e in _events(cf, stack_id)}
    stack = _change_set(ctx, cf, stack_id, {**inside, "C": outside}, wait_timeout_s=_DEADLINE_S)
    assert stack["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"a write outside the role's policy must fail: {stack['StackStatus']!r}")
    assert stack.get("RoleARN") == role_arn, stack.get("RoleARN")
    reasons = _create_failed_reasons(cf, stack_id, before, "C")
    assert len(reasons) == 1, reasons
    # The SSM::Parameter resource handler's own denial carries no IAM principal, action or
    # policy detail: it is this fixed, generic text rather than an SDK AccessDenied.
    assert _DENIED.match(reasons[0]), f"C CREATE_FAILED reason: {reasons[0]!r}"
    ssm = ctx.client("ssm")
    got = _error(lambda: ssm.get_parameter(Name=outside))
    assert got == ("ParameterNotFound", ""), f"denied parameter must not exist: {got!r}"

    # The kept role still works for a write inside its policy: the denial above was the
    # resource, not a broken role or a stack stuck after rollback.
    inside["D"] = f"{prefix}/d"
    stack = _change_set(ctx, cf, stack_id, inside)
    assert stack["StackStatus"] == "UPDATE_COMPLETE", f"restore update: {stack['StackStatus']!r}"
    assert stack.get("RoleARN") == role_arn, stack.get("RoleARN")
    assert ssm.get_parameter(Name=f"{prefix}/d")["Parameter"]["Value"] == "D", "D not written"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
