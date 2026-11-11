"""cfn-iam-managed-policy-instance-profile-and-inline-policies-read-back-then-removed-on-delete."""
from __future__ import annotations

import json
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-managed-policy-instance-profile-and-inline-policies-read-back-then-removed-on-delete"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "iam"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


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
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

def _doc(doc):
    """IAM echoes PolicyDocument as a URL-encoded JSON string on some calls, a dict on others."""
    return doc if isinstance(doc, dict) else json.loads(urllib.parse.unquote(doc))


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed ManagedPolicy, InstanceProfile, legacy inline Policy and
    RolePolicy are all real at IAM: each reads back the template's own values, and deleting the
    stack removes every one of them from IAM, not just from CFN.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    stack_name = ctx.unique_name("sim2real-behav-cfn-iampl-")
    policy_name = ctx.unique_name("sim2real-behav-mp-")
    description = ctx.unique_name("sim2real-desc-")
    inline_name = ctx.unique_name("sim2real-behav-inline-")
    rolepolicy_name = ctx.unique_name("sim2real-behav-rp-")
    bucket_name = ctx.unique_name("sim2real-behav-bucket-").lower()

    def docs(s3_arn):
        """(managed, inline, role policy) documents, each S3 ARN built by ``s3_arn(suffix)``."""
        return (
            {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket",
                            "Resource": s3_arn(bucket_name)}]},
            {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                            "Resource": s3_arn(f"{bucket_name}/*")}]},
            {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": "s3:GetBucketLocation",
                            "Resource": s3_arn(bucket_name)}]},
        )

    managed_tpl, inline_tpl, rolepolicy_tpl = docs(
        lambda suffix: {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{suffix}"})
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {"AssumeRolePolicyDocument": trust},
            },
            "ManagedPolicy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": policy_name,
                    "Description": description,
                    "PolicyDocument": managed_tpl,
                    "Roles": [{"Ref": "Role"}],
                },
            },
            "InlinePolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": inline_name,
                    "PolicyDocument": inline_tpl,
                    "Roles": [{"Ref": "Role"}],
                },
            },
            "RolePolicy": {
                "Type": "AWS::IAM::RolePolicy",
                "Properties": {
                    "RoleName": {"Ref": "Role"},
                    "PolicyName": rolepolicy_name,
                    "PolicyDocument": rolepolicy_tpl,
                },
            },
            "InstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {"Roles": [{"Ref": "Role"}]},
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "ManagedPolicyArn": {"Value": {"Ref": "ManagedPolicy"}},
            "InstanceProfileRef": {"Value": {"Ref": "InstanceProfile"}},
            "InstanceProfileArn": {"Value": {"Fn::GetAtt": ["InstanceProfile", "Arn"]}},
        },
    })

    stack_id = create_stack(ctx, cfn, stack_name, template, Capabilities=["CAPABILITY_NAMED_IAM"])
    created = wait_stack(cfn, stack_id)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    partition = stack_id.split(":")[1]
    managed_doc, inline_doc, rolepolicy_doc = docs(lambda suffix: f"arn:{partition}:s3:::{suffix}")

    role_name = cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="Role"
    )["StackResourceDetail"]["PhysicalResourceId"]
    outputs = stack_outputs(cfn, stack_id)

    # ---- ManagedPolicy: Ref is the policy's own ARN; GetPolicy and GetPolicyVersion read back
    # the template's declared Description and PolicyDocument.
    policy_arn = outputs["ManagedPolicyArn"]
    want_arn = f"arn:{partition}:iam::{ctx.account}:policy/{policy_name}"
    assert policy_arn == want_arn, f"ManagedPolicy Ref {policy_arn!r}, expected {want_arn!r}"
    policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    got = (policy["PolicyName"], policy["Arn"])
    assert got == (policy_name, want_arn), (
        f"GetPolicy (PolicyName, Arn) {got!r}, expected {(policy_name, want_arn)!r}"
    )
    assert policy["Description"] == description, (
        f"expected Description {description!r}, got {policy.get('Description')!r}"
    )
    version = iam.get_policy_version(
        PolicyArn=policy_arn, VersionId=policy["DefaultVersionId"]
    )["PolicyVersion"]
    assert _doc(version["Document"]) == managed_doc, (
        f"expected the declared policy document {managed_doc!r}, got {_doc(version['Document'])!r}"
    )

    # The ManagedPolicy's Roles property attached it to the role.
    attached = [(p["PolicyName"], p["PolicyArn"]) for p in
                paginate(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=role_name)]
    assert attached == [(policy_name, want_arn)], (
        f"role {role_name!r} attached policies {attached!r}, expected {[(policy_name, want_arn)]!r}"
    )

    # ---- The legacy inline AWS::IAM::Policy: Ref is a generated id, so verify by role + policy
    # name instead.
    inline = iam.get_role_policy(RoleName=role_name, PolicyName=inline_name)
    assert _doc(inline["PolicyDocument"]) == inline_doc, (
        f"expected the declared inline policy document {inline_doc!r}, "
        f"got {_doc(inline['PolicyDocument'])!r}"
    )

    # ---- AWS::IAM::RolePolicy: the standalone resource, scoped to one role directly.
    rp = iam.get_role_policy(RoleName=role_name, PolicyName=rolepolicy_name)
    assert _doc(rp["PolicyDocument"]) == rolepolicy_doc, (
        f"expected the declared RolePolicy document {rolepolicy_doc!r}, got {_doc(rp['PolicyDocument'])!r}"
    )

    # ---- AWS::IAM::InstanceProfile: Ref is the InstanceProfileName; GetInstanceProfile reads
    # back the role it was attached to and matches the GetAtt Arn output.
    profile_name = outputs["InstanceProfileRef"]
    profile = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
    assert outputs["InstanceProfileArn"] == profile["Arn"], (
        f"GetAtt InstanceProfile.Arn was {outputs['InstanceProfileArn']!r}, "
        f"IAM's own Arn is {profile['Arn']!r}"
    )
    profile_roles = [r["RoleName"] for r in profile["Roles"]]
    assert profile_roles == [role_name], (
        f"expected the instance profile to carry role {role_name!r}, got {profile_roles!r}"
    )

    delete_stack(cfn, stack_id)

    # The physical deletes may lag DELETE_COMPLETE: poll each read to its refusal, then grade it.
    policy_gone = ("NoSuchEntity", f"Policy {policy_arn} was not found.")
    until_raises(lambda: iam.get_policy(PolicyArn=policy_arn), timeout_s=120.0)
    expect_error(lambda: iam.get_policy(PolicyArn=policy_arn), *policy_gone)

    profile_gone = ("NoSuchEntity", f"Instance Profile {profile_name} cannot be found.")
    until_raises(lambda: iam.get_instance_profile(InstanceProfileName=profile_name),
                 timeout_s=120.0)
    expect_error(lambda: iam.get_instance_profile(InstanceProfileName=profile_name),
                 *profile_gone)

    role_gone = ("NoSuchEntity", f"The role with name {role_name} cannot be found.")
    until_raises(lambda: iam.get_role(RoleName=role_name), timeout_s=120.0)
    expect_error(lambda: iam.get_role(RoleName=role_name), *role_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
