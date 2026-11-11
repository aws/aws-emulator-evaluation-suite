"""deploy-iam-1-cfn-rollback-and-trust-flip-assume-denied."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iam-1-cfn-rollback-and-trust-flip-assume-denied"
GROUP = "deploy-iam-cfn-update-rollback"
SERVICES = ["cloudformation", "iam", "sts"]

_NAMED = ["CAPABILITY_NAMED_IAM"]
_IAM_ONLY = ["CAPABILITY_IAM"]
# Trust-policy revocation reaches sts:AssumeRole eventually; the ceiling bounds the wait.
_TRUST_REVOKE_CEILING_S = 480
_IAM_MALFORMED_MSG = "Policy statement must contain resources."
_NAMED_IAM_REFUSAL = "Requires capabilities : [CAPABILITY_NAMED_IAM]"
_TRUSTED_SESSION = "sim2real-trusted"
# CloudFormation's resource-handler wrapping of the downstream IAM error; Request ID and
# RequestToken are AWS-generated and graded by form.
_CFN_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z]+), '
    r'Status Code: (?P<status>\d+), Request ID: (?P<request_id>[0-9a-f-]+)\) '
    r'\(SDK Attempt Count: \d+\)" '
    r'\(RequestToken: (?P<token>[0-9a-f-]+), HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c7",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A failed create rolls back and deletes the role it had created; an in-place trust flip keeps
    the RoleId and makes AssumeRole return AccessDenied; a RoleName change replaces the role; and
    CAPABILITY_IAM alone is refused for named IAM resources on create and update.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    caller = sts.get_caller_identity()
    account = caller["Account"]
    caller_arn = caller["Arn"]
    tags_ = [{"Key": "sim2real", "Value": CHECK}]

    # Stack 1 is started first, asynchronously; it rolls back while stack 2 is exercised.
    s1 = ctx.unique_name("sim2real-xsvc-dirb-")
    role_a = f"{s1}-a"
    pol_name = f"{s1}-p"
    pol_path = f"/{s1}/"
    bad_doc = {"Version": "2012-10-17",
               "Statement": [{"Effect": "Allow", "Action": "s3:GetObject"}]}  # no Resource
    tpl1 = {
        "Resources": {
            "RoleA": {"Type": "AWS::IAM::Role", "Properties": {
                "RoleName": role_a,
                "AssumeRolePolicyDocument": _trust({"AWS": f"arn:aws:iam::{account}:root"}),
            }},
            "BadPolicy": {"Type": "AWS::IAM::ManagedPolicy", "DependsOn": "RoleA", "Properties": {
                "ManagedPolicyName": pol_name,
                "Path": pol_path,
                "Roles": [{"Ref": "RoleA"}],
                "PolicyDocument": bad_doc,
            }},
        }
    }
    cfn.create_stack(StackName=s1, TemplateBody=json.dumps(tpl1), Capabilities=_NAMED, Tags=tags_)
    ctx.on_cleanup(lambda: _delete_stack(cfn, s1))

    # The capability gate refuses CAPABILITY_IAM for a named role.
    s2 = ctx.unique_name("sim2real-xsvc-ditr-")
    r1 = f"{s2}-r1"
    r2 = f"{s2}-r2"
    ctx.on_cleanup(lambda: _delete_stack(cfn, s2))  # harmless no-op if the stack never exists
    caller_trust = {"AWS": f"arn:aws:iam::{account}:root"}
    code, msg = _error(lambda: cfn.create_stack(
        StackName=s2, TemplateBody=_role_template(r1, caller_trust), Capabilities=_IAM_ONLY,
        Tags=tags_))
    assert code == "InsufficientCapabilitiesException", (
        f"create_stack with only CAPABILITY_IAM for a named role returned {code!r} ({msg!r}); "
        f"expected InsufficientCapabilitiesException"
    )
    assert msg == _NAMED_IAM_REFUSAL, f"refusal message {msg!r} != {_NAMED_IAM_REFUSAL!r}"
    code, msg = _error(lambda: cfn.describe_stacks(StackName=s2))
    assert code == "ValidationError", (
        f"a refused create must leave no stack behind; describe_stacks returned {code!r} ({msg!r})"
    )
    assert msg == _no_stack(s2), f"describe_stacks message {msg!r} != {_no_stack(s2)!r}"
    _assert_no_role(iam, r1, "a refused create must create no role")

    # Positive control: the same template with CAPABILITY_NAMED_IAM deploys.
    cfn.create_stack(StackName=s2, TemplateBody=_role_template(r1, caller_trust),
                     Capabilities=_NAMED, Tags=tags_)
    status = _wait_stack(cfn, s2, timeout_s=300)
    assert status == "CREATE_COMPLETE", f"stack 2 create ended {status!r}, expected CREATE_COMPLETE"
    role = iam.get_role(RoleName=r1)["Role"]
    role_id = role["RoleId"]
    role_arn = role["Arn"]
    out = {o["OutputKey"]: o["OutputValue"]
           for o in cfn.describe_stacks(StackName=s2)["Stacks"][0].get("Outputs", [])}
    assert out.get("RoleId") == role_id, (
        f"stack output Fn::GetAtt RoleId {out.get('RoleId')!r} != IAM RoleId {role_id!r}"
    )
    principal = role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]
    assert principal == {"AWS": f"arn:aws:iam::{account}:root"}, (
        f"deployed trust principal is {principal!r}, expected the caller account root"
    )

    # The role functions: the caller can assume it (bounded retry on IAM propagation only).
    assumed = _assume_until_allowed(sts, role_arn, timeout_s=_budget_s(ctx, 90.0))
    assumed_id = assumed["AssumedRoleUser"]["AssumedRoleId"]
    expected_assumed_id = f"{role_id}:{_TRUSTED_SESSION}"
    assert assumed_id == expected_assumed_id, (
        f"assumed session id {assumed_id!r} != {expected_assumed_id!r}"
    )

    # In-place update: flip the trust to a foreign (service) principal.
    foreign = {"Service": "ec2.amazonaws.com"}
    cfn.update_stack(StackName=s2, TemplateBody=_role_template(r1, foreign), Capabilities=_NAMED)
    status = _wait_stack(cfn, s2, timeout_s=300, prior="CREATE_COMPLETE")
    assert status == "UPDATE_COMPLETE", f"trust update ended {status!r}, expected UPDATE_COMPLETE"
    after = iam.get_role(RoleName=r1)["Role"]
    assert after["RoleId"] == role_id, (
        f"a trust-policy update must not replace the role: RoleId {role_id!r} -> {after['RoleId']!r}"
    )
    assert after["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] == foreign, (
        f"persisted trust principal is "
        f"{after['AssumeRolePolicyDocument']['Statement'][0]['Principal']!r}, expected {foreign!r}"
    )
    _assume_until_denied(sts, role_arn, caller_arn, timeout_s=_TRUST_REVOKE_CEILING_S)
    assert iam.get_role(RoleName=r1)["Role"]["RoleId"] == role_id, (
        "RoleId changed while the trust revocation propagated"
    )

    # The update path enforces the capability gate too, and a refused update changes nothing.
    code, msg = _error(lambda: cfn.update_stack(
        StackName=s2, TemplateBody=_role_template(r2, foreign), Capabilities=_IAM_ONLY))
    assert code == "InsufficientCapabilitiesException", (
        f"update_stack with only CAPABILITY_IAM returned {code!r} ({msg!r}); "
        f"expected InsufficientCapabilitiesException"
    )
    assert msg == _NAMED_IAM_REFUSAL, f"refusal message {msg!r} != {_NAMED_IAM_REFUSAL!r}"
    st = cfn.describe_stacks(StackName=s2)["Stacks"][0]["StackStatus"]
    assert st == "UPDATE_COMPLETE", f"a refused update moved the stack to {st!r}"
    _assert_no_role(iam, r2, "a refused update must not create the role")

    # Replacing update: RoleName is a replacement property.
    cfn.update_stack(StackName=s2, TemplateBody=_role_template(r2, foreign), Capabilities=_NAMED)
    status = _wait_stack(cfn, s2, timeout_s=300, prior="UPDATE_COMPLETE")
    assert status == "UPDATE_COMPLETE", f"rename update ended {status!r}, expected UPDATE_COMPLETE"
    new_role = iam.get_role(RoleName=r2)["Role"]
    assert new_role["RoleId"] != role_id, (
        f"renaming must replace the role, but RoleId {new_role['RoleId']!r} is unchanged"
    )
    _assert_no_role(iam, r1, "the replaced role must be deleted after UPDATE_COMPLETE")
    phys = cfn.describe_stack_resource(StackName=s2, LogicalResourceId="Role")[
        "StackResourceDetail"]["PhysicalResourceId"]
    assert phys == r2, f"stack resource physical id is {phys!r}, expected the new name {r2!r}"

    # Stack 1 outcome: rollback undid the role it had created.
    status = _wait_stack(cfn, s1, timeout_s=420)
    assert status == "ROLLBACK_COMPLETE", f"stack 1 ended {status!r}, expected ROLLBACK_COMPLETE"
    events = _events(cfn, s1)  # oldest first
    seq = [(e["LogicalResourceId"], e["ResourceStatus"]) for e in events]
    i_a_ok = _index(seq, ("RoleA", "CREATE_COMPLETE"))
    i_p_fail = _index(seq, ("BadPolicy", "CREATE_FAILED"))
    i_a_del = _index(seq, ("RoleA", "DELETE_COMPLETE"))
    assert i_a_ok is not None and i_p_fail is not None and i_a_del is not None, (
        f"stack 1 events lack RoleA CREATE_COMPLETE / BadPolicy CREATE_FAILED / "
        f"RoleA DELETE_COMPLETE: {seq!r}"
    )
    assert i_a_ok < i_p_fail < i_a_del, (
        f"expected role created, then policy failed, then role rolled back; got order {seq!r}"
    )
    # The CFN reason wraps the IAM error; its Request ID and RequestToken are AWS-generated.
    reason = events[i_p_fail].get("ResourceStatusReason") or ""
    parsed = _CFN_REASON.match(reason)
    assert parsed is not None, (
        f"BadPolicy CREATE_FAILED reason is not a forwarded resource-handler error: {reason!r}"
    )
    assert parsed["message"] == _IAM_MALFORMED_MSG, (
        f"forwarded message {parsed['message']!r} != {_IAM_MALFORMED_MSG!r}"
    )
    assert (parsed["service"], parsed["status"], parsed["handler"]) == ("Iam", "400", "InvalidRequest"), (
        f"forwarded from service {parsed['service']!r} status {parsed['status']!r} handler "
        f"{parsed['handler']!r}; expected ('Iam', '400', 'InvalidRequest')"
    )
    assert _UUID_RE.match(parsed["request_id"]), f"Request ID not a uuid: {parsed['request_id']!r}"
    assert _UUID_RE.match(parsed["token"]), f"RequestToken not a uuid: {parsed['token']!r}"
    assert events[i_a_ok].get("PhysicalResourceId") == role_a, (
        f"RoleA physical id {events[i_a_ok].get('PhysicalResourceId')!r} != pinned name {role_a!r}"
    )
    _assert_no_role(iam, role_a, "the rolled-back role must not resolve")
    leaked = _local_policies(iam, pol_path)
    assert leaked == [], f"the failed managed policy exists under {pol_path!r}: {leaked!r}"

    # The same document sent straight to IAM is the MalformedPolicyDocument that CFN wrapped.
    pol_arn = f"arn:aws:iam::{account}:policy{pol_path}{pol_name}"
    ctx.on_cleanup(lambda: _delete_policy(iam, pol_arn))  # no-op unless IAM wrongly accepts
    code, msg = _error(lambda: iam.create_policy(
        PolicyName=pol_name, Path=pol_path, PolicyDocument=json.dumps(bad_doc)))
    assert code == "MalformedPolicyDocument", (
        f"IAM CreatePolicy with the same document returned {code!r} ({msg!r})"
    )
    assert msg == _IAM_MALFORMED_MSG, f"IAM message {msg!r} != {_IAM_MALFORMED_MSG!r}"

    stack_ids = [cfn.describe_stacks(StackName=s)["Stacks"][0]["StackId"] for s in (s1, s2)]
    cfn.delete_stack(StackName=s1)
    cfn.delete_stack(StackName=s2)
    for stack_id in stack_ids:
        _wait_gone(cfn, stack_id, timeout_s=300)
    for name in (role_a, r1, r2):
        _assert_no_role(iam, name, "the role must not survive stack deletion")


def _trust(principal):
    return {"Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}]}


def _role_template(role_name, principal):
    return json.dumps({
        "Resources": {"Role": {"Type": "AWS::IAM::Role", "Properties": {
            "RoleName": role_name, "AssumeRolePolicyDocument": _trust(principal)}}},
        "Outputs": {"RoleId": {"Value": {"Fn::GetAtt": ["Role", "RoleId"]}}},
    })


def _error(fn):
    """(code, message) of the ClientError fn raises. RAISES if fn() succeeds."""
    try:
        ok = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail, but it succeeded and returned {ok!r}")


def _no_stack(name):
    return f"Stack with id {name} does not exist"


def _assert_no_role(iam, name, why):
    code, msg = _error(lambda: iam.get_role(RoleName=name))
    assert code == "NoSuchEntity", f"{why}: get_role({name!r}) -> {code!r} ({msg!r})"
    expected = f"The role with name {name} cannot be found."
    assert msg == expected, f"{why}: get_role message {msg!r} != {expected!r}"


def _wait_stack(cfn, name, timeout_s, prior=None):
    """The first settled status; with ``prior``, the status the operation started from, a settled
    read counts only after another status is seen."""
    deadline = time.monotonic() + timeout_s
    status = None
    moved = prior is None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        moved = moved or status != prior
        if moved and not status.endswith("_IN_PROGRESS"):
            return status
        time.sleep(5)
    raise AssertionError(f"stack {name} still {status!r} after {timeout_s}s")


def _wait_gone(cfn, stack_id, timeout_s):
    """Poll a deleted stack by StackId until DELETE_COMPLETE or DELETE_FAILED and require DELETE_COMPLETE."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in ("DELETE_COMPLETE", "DELETE_FAILED") or time.monotonic() >= deadline:
            break
        time.sleep(5)
    assert status == "DELETE_COMPLETE", f"stack {stack_id} is {status!r} after DeleteStack"


def _events(cfn, name):
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=name):
        out.extend(page["StackEvents"])
    return sorted(out, key=lambda e: e["Timestamp"])


def _index(seq, item):
    for i, x in enumerate(seq):
        if x == item:
            return i
    return None


def _local_policies(iam, path_prefix):
    names = []
    for page in iam.get_paginator("list_policies").paginate(Scope="Local", PathPrefix=path_prefix):
        names.extend(p["PolicyName"] for p in page["Policies"])
    return names


def _assume_until_allowed(sts, role_arn, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=_TRUSTED_SESSION,
                                   DurationSeconds=900)
        except ClientError as e:
            last = e.response["Error"]["Code"]
            if last != "AccessDenied":
                raise
        time.sleep(3)
    raise AssertionError(f"caller-trusting role never became assumable in {timeout_s}s (last {last!r})")


def _assume_until_denied(sts, role_arn, caller_arn, timeout_s):
    """Poll AssumeRole until it returns AccessDenied three times in a row; return that count."""
    expected = f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: {role_arn}"

    deadline = time.monotonic() + timeout_s
    streak = 0
    while time.monotonic() < deadline:
        try:
            sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-revoked",
                            DurationSeconds=900)
            streak = 0
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message")
            assert code == "AccessDenied", f"revoked AssumeRole returned {code!r}, expected AccessDenied"
            assert msg == expected, f"revoked AssumeRole message {msg!r} != {expected!r}"
            streak += 1
            if streak >= 3:
                return streak
        time.sleep(5)
    raise AssertionError(
        f"AssumeRole still succeeds {timeout_s}s after the trust was flipped to a foreign principal"
    )


def _delete_policy(iam, arn):
    try:
        iam.delete_policy(PolicyArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise RuntimeError(f"policy {arn}: {e}") from e


def _delete_stack(cfn, name):
    try:
        try:
            stack_id = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except ClientError as e:
            if e.response["Error"]["Message"] == _no_stack(name):
                return
            raise
        cfn.delete_stack(StackName=stack_id)
        _wait_gone(cfn, stack_id, timeout_s=300)
    except Exception as e:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {name}: {e!r}") from e


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
