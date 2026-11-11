"""deploy-s3-access-grants-instance-location-grant-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3-access-grants-instance-location-grant-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3control"]

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

_NO_INSTANCE = ("AccessGrantsInstanceNotExistsError", "Access Grants Instance does not exist")
_NO_GRANT = ("NoSuchAccessGrantError", "The specified access grant does not exist")
_NO_LOCATION = ("NoSuchAccessGrantsLocationError", "The specified access grants location does not exist")


def _list_all(call, key, **kw):
    """Every item under ``key`` across all NextToken pages (S3 Control ships no paginator)."""
    items, token = [], None
    while True:
        page = call(**kw, **({"NextToken": token} if token else {}))
        items += page.get(key, [])
        token = page.get("NextToken")
        if not token:
            return items


@tags(
    "axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control",
    "resource:account-singleton:s3-access-grants-instance",
)
def run(ctx) -> None:
    """A single CloudFormation stack provisions an AWS::S3::AccessGrantsInstance, an
    AWS::S3::AccessGrantsLocation and an AWS::S3::AccessGrant; each read back through S3 Control,
    and the stack delete removes all three."""
    cf = ctx.client("cloudformation")
    s3c = ctx.client("s3control")
    account = ctx.account
    stack_name = ctx.unique_name("sim2real-behav-cfn-ag-")
    bucket = ctx.unique_name("sim2real-behav-cfn-ag-").lower()[:63]
    location_role = ctx.unique_name("sim2real-behav-cfn-aglocrole-")
    grantee_role = ctx.unique_name("sim2real-behav-cfn-aggrantee-")

    # The instance is one per account and region: this check needs the account to have none yet.
    try:
        prior = s3c.get_access_grants_instance(AccountId=account)
    except ClientError as exc:
        prior_error = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        assert prior_error == _NO_INSTANCE, (
            f"precondition: GetAccessGrantsInstance before the deploy answered {prior_error!r}"
        )
    else:
        raise AssertionError(
            f"precondition: the account already has an Access Grants instance in {ctx.region}: "
            f"{prior.get('AccessGrantsInstanceArn')!r}"
        )

    location_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "access-grants.s3.amazonaws.com"},
            "Action": ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:SetContext"],
        }],
    }
    grantee_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
            "Action": "sts:AssumeRole",
        }],
    }

    template = json.dumps({
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket}},
            "LocationRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": location_role,
                    "AssumeRolePolicyDocument": location_trust,
                    "Policies": [{
                        "PolicyName": "grants-access",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetObjectVersion"],
                                "Resource": [
                                    {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}"},
                                    {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}/*"},
                                ],
                            }],
                        },
                    }],
                },
            },
            "GranteeRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"RoleName": grantee_role, "AssumeRolePolicyDocument": grantee_trust},
            },
            "Instance": {"Type": "AWS::S3::AccessGrantsInstance", "Properties": {}},
            "Location": {
                "Type": "AWS::S3::AccessGrantsLocation",
                "DependsOn": "Instance",
                "Properties": {
                    "IamRoleArn": {"Fn::GetAtt": ["LocationRole", "Arn"]},
                    "LocationScope": {"Fn::Sub": "s3://${Bucket}/"},
                },
            },
            "Grant": {
                "Type": "AWS::S3::AccessGrant",
                "Properties": {
                    "AccessGrantsLocationId": {"Ref": "Location"},
                    "AccessGrantsLocationConfiguration": {"S3SubPrefix": "data/*"},
                    "Grantee": {
                        "GranteeType": "IAM",
                        "GranteeIdentifier": {"Fn::GetAtt": ["GranteeRole", "Arn"]},
                    },
                    "Permission": "READ",
                },
            },
        },
        "Outputs": {
            "InstanceRef": {"Value": {"Ref": "Instance"}},
            "InstanceId": {"Value": {"Fn::GetAtt": ["Instance", "AccessGrantsInstanceId"]}},
            "LocationRef": {"Value": {"Ref": "Location"}},
            "LocationArn": {"Value": {"Fn::GetAtt": ["Location", "AccessGrantsLocationArn"]}},
            "GrantRef": {"Value": {"Ref": "Grant"}},
            "GrantArn": {"Value": {"Fn::GetAtt": ["Grant", "AccessGrantArn"]}},
            "GrantScope": {"Value": {"Fn::GetAtt": ["Grant", "GrantScope"]}},
            "LocationRoleArn": {"Value": {"Fn::GetAtt": ["LocationRole", "Arn"]}},
            "GranteeRoleArn": {"Value": {"Fn::GetAtt": ["GranteeRole", "Arn"]}},
        },
    })

    stack_id = create_stack(ctx, cf, stack_name, template, Capabilities=["CAPABILITY_NAMED_IAM"])
    created = wait_stack(cf, stack_id)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )

    outputs = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    expected_instance_arn = f"arn:{partition}:s3:{ctx.region}:{account}:access-grants/default"
    assert outputs["InstanceRef"] == expected_instance_arn, (
        f"Ref of Instance was {outputs['InstanceRef']!r}, expected {expected_instance_arn!r}"
    )
    assert outputs["InstanceId"] == "default", f"GetAtt AccessGrantsInstanceId was {outputs['InstanceId']!r}"

    location_id = outputs["LocationRef"]
    expected_location_arn = (
        f"arn:{partition}:s3:{ctx.region}:{account}:access-grants/default/location/{location_id}"
    )
    assert outputs["LocationArn"] == expected_location_arn, (
        f"GetAtt AccessGrantsLocationArn was {outputs['LocationArn']!r}"
    )

    grant_id = outputs["GrantRef"]
    expected_grant_arn = (
        f"arn:{partition}:s3:{ctx.region}:{account}:access-grants/default/grant/{grant_id}"
    )
    assert outputs["GrantArn"] == expected_grant_arn, f"GetAtt AccessGrantArn was {outputs['GrantArn']!r}"
    expected_grant_scope = f"s3://{bucket}/data/*"
    assert outputs["GrantScope"] == expected_grant_scope, f"GetAtt GrantScope was {outputs['GrantScope']!r}"

    # Independent reads at the owning service: S3 Control's own records, listed by scope.
    locations = [(loc["AccessGrantsLocationId"], loc["AccessGrantsLocationArn"])
                 for loc in _list_all(s3c.list_access_grants_locations, "AccessGrantsLocationsList",
                                      AccountId=account, LocationScope=f"s3://{bucket}/")]
    assert locations == [(location_id, expected_location_arn)], (
        f"ListAccessGrantsLocations by scope lists {locations!r}; Ref/GetAtt are "
        f"{(location_id, expected_location_arn)!r}"
    )
    grants = [(g["AccessGrantId"], g["AccessGrantArn"])
              for g in _list_all(s3c.list_access_grants, "AccessGrantsList",
                                 AccountId=account, GrantScope=expected_grant_scope)]
    assert grants == [(grant_id, expected_grant_arn)], (
        f"ListAccessGrants by scope lists {grants!r}; Ref/GetAtt are {(grant_id, expected_grant_arn)!r}"
    )
    instance_got = s3c.get_access_grants_instance(AccountId=account)
    assert instance_got["AccessGrantsInstanceArn"] == expected_instance_arn, (
        f"GetAccessGrantsInstance arn {instance_got['AccessGrantsInstanceArn']!r}"
    )
    assert instance_got["AccessGrantsInstanceId"] == "default", (
        f"GetAccessGrantsInstance id {instance_got['AccessGrantsInstanceId']!r}"
    )

    location_got = s3c.get_access_grants_location(AccountId=account, AccessGrantsLocationId=location_id)
    assert location_got["LocationScope"] == f"s3://{bucket}/", (
        f"GetAccessGrantsLocation LocationScope {location_got['LocationScope']!r}"
    )
    assert location_got["IAMRoleArn"] == outputs["LocationRoleArn"], (
        f"GetAccessGrantsLocation IAMRoleArn {location_got['IAMRoleArn']!r}"
    )

    grant_got = s3c.get_access_grant(AccountId=account, AccessGrantId=grant_id)
    assert grant_got["Grantee"] == {
        "GranteeType": "IAM", "GranteeIdentifier": outputs["GranteeRoleArn"],
    }, f"GetAccessGrant Grantee {grant_got['Grantee']!r}"
    assert grant_got["Permission"] == "READ", f"GetAccessGrant Permission {grant_got['Permission']!r}"
    assert grant_got["AccessGrantsLocationId"] == location_id, (
        f"GetAccessGrant AccessGrantsLocationId {grant_got['AccessGrantsLocationId']!r}"
    )
    assert grant_got["AccessGrantsLocationConfiguration"] == {"S3SubPrefix": "data/*"}, (
        f"GetAccessGrant AccessGrantsLocationConfiguration {grant_got['AccessGrantsLocationConfiguration']!r}"
    )
    assert grant_got["GrantScope"] == expected_grant_scope, f"GetAccessGrant GrantScope {grant_got['GrantScope']!r}"

    delete_stack(cf, stack_id)

    until_raises(lambda: s3c.get_access_grant(AccountId=account, AccessGrantId=grant_id), 60.0)
    expect_error(lambda: s3c.get_access_grant(AccountId=account, AccessGrantId=grant_id), *_NO_GRANT)
    until_raises(lambda: s3c.get_access_grants_location(
        AccountId=account, AccessGrantsLocationId=location_id), 60.0)
    expect_error(lambda: s3c.get_access_grants_location(
        AccountId=account, AccessGrantsLocationId=location_id), *_NO_LOCATION)
    until_raises(lambda: s3c.get_access_grants_instance(AccountId=account), 60.0)
    expect_error(lambda: s3c.get_access_grants_instance(AccountId=account), *_NO_INSTANCE)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
