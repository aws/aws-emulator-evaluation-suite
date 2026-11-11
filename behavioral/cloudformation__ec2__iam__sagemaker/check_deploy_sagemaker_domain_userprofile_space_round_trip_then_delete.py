"""deploy-sagemaker-domain-userprofile-space-round-trip-then-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sagemaker-domain-userprofile-space-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "iam", "sagemaker"]

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

_SM_TERMINAL = frozenset({"InService", "Failed", "Deleted"})


def _poll_until(probe, terminal, *, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while value not in terminal:
        if time.monotonic() >= deadline:
            raise AssertionError(f"status stuck at {value!r} after {timeout_s:.0f}s")
        time.sleep(interval_s)
        value = probe()
    return value


def _template(domain_name, user_profile_name, space_name, vpc_id, subnet_id, role_arn,
              children=True):
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Domain": {
                "Type": "AWS::SageMaker::Domain",
                "Properties": {
                    "DomainName": domain_name,
                    "AuthMode": "IAM",
                    "VpcId": vpc_id,
                    "SubnetIds": [subnet_id],
                    "HomeEfsFileSystemCreation": "Disabled",
                    "DefaultUserSettings": {"ExecutionRole": role_arn},
                    "DefaultSpaceSettings": {"ExecutionRole": role_arn},
                },
            },
            "UserProfile": {
                "Type": "AWS::SageMaker::UserProfile",
                "Properties": {
                    "DomainId": {"Fn::GetAtt": ["Domain", "DomainId"]},
                    "UserProfileName": user_profile_name,
                },
            },
            "Space": {
                "Type": "AWS::SageMaker::Space",
                "Properties": {
                    "DomainId": {"Fn::GetAtt": ["Domain", "DomainId"]},
                    "SpaceName": space_name,
                },
            },
        },
        "Outputs": {
            "DomainId": {"Value": {"Fn::GetAtt": ["Domain", "DomainId"]}},
            "DomainArn": {"Value": {"Fn::GetAtt": ["Domain", "DomainArn"]}},
            "DomainRef": {"Value": {"Ref": "Domain"}},
            "UserProfileRef": {"Value": {"Ref": "UserProfile"}},
            "UserProfileArn": {"Value": {"Fn::GetAtt": ["UserProfile", "UserProfileArn"]}},
            "SpaceRef": {"Value": {"Ref": "Space"}},
            "SpaceArn": {"Value": {"Fn::GetAtt": ["Space", "SpaceArn"]}},
        },
    }
    if not children:
        for key in ("UserProfile", "Space"):
            del template["Resources"][key]
        template["Outputs"] = {k: v for k, v in template["Outputs"].items()
                               if k.startswith("Domain")}
    return json.dumps(template)


def _vpc_subnet(ctx, ec2):
    """A fresh, disposable VPC+subnet (never the account's default VPC)."""
    vpc_name = ctx.unique_name("sim2real-smdomain-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.197.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": vpc_name}, {"Key": "sim2real", "Value": vpc_name}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_name = ctx.unique_name("sim2real-smdomain-subnet-")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.197.0.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Name", "Value": subnet_name},
                     {"Key": "sim2real", "Value": subnet_name}],
        }],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return vpc_id, subnet_id


def _retry_delete(fn, attempts: int = 15, delay: float = 10.0) -> None:
    for i in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            # Only a dependency still detaching is retried; any other refusal raises now.
            if exc.response["Error"].get("Code") != "DependencyViolation" or i == attempts - 1:
                raise
            time.sleep(delay)


def _role(ctx, iam):
    role_name = ctx.unique_name("sim2real-smdomain-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _teardown_role(iam, role_name))
    return role_arn, role_name


def _teardown_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _not_found(partition, region, account, resource_path):
    kind, path = resource_path
    arn = f"arn:{partition}:sagemaker:{region}:{account}:{path}"
    return ("ResourceNotFound", f"{kind} [{arn}] does not exist.")


def _own_tags(sm, arn):
    """The resource's tags as {key: value}, without the ``aws:`` system tags."""
    rows = paginate(sm, "list_tags", "Tags", ResourceArn=arn)
    return {r["Key"]: r["Value"] for r in rows if not r["Key"].startswith("aws:")}


def _delete_nfs_security_groups(ec2, vpc_id, domain_id, attempts: int = 20, delay: float = 10.0) -> None:
    """A Domain provisions an inbound/outbound NFS security group pair even with EFS creation
    disabled; delete them (revoking their mutual rules first) so the VPC teardown is unblocked.
    """
    names = [f"security-group-for-inbound-nfs-{domain_id}", f"security-group-for-outbound-nfs-{domain_id}"]
    groups = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": names}]
    )["SecurityGroups"]
    for g in groups:
        if g["IpPermissions"]:
            ec2.revoke_security_group_ingress(GroupId=g["GroupId"], IpPermissions=g["IpPermissions"])
        if g["IpPermissionsEgress"]:
            ec2.revoke_security_group_egress(GroupId=g["GroupId"], IpPermissions=g["IpPermissionsEgress"])
    for g in groups:
        _retry_delete(lambda gid=g["GroupId"]: ec2.delete_security_group(GroupId=gid),
                      attempts=attempts, delay=delay)


def _domain_physical_id(cf, stack_id):
    """The Domain's PhysicalResourceId if CloudFormation ever created it, else None.

    Read even after a rollback, so the NFS security-group cleanup can find a domain that was
    created and then torn down by CloudFormation's own rollback.
    """
    try:
        detail = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Domain")
    except ClientError:
        return None
    return detail["StackResourceDetail"].get("PhysicalResourceId")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation SageMaker Domain, UserProfile and Space read back through SageMaker.

    Ref, GetAtt, properties and tags match; an update dropping the profile and space removes both
    while the domain answers, and the stack delete removes the domain.
    """
    cf = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    vpc_id, subnet_id = _vpc_subnet(ctx, ec2)
    role_arn, _role_name = _role(ctx, iam)

    # A Domain provisions its NFS security-group pair unconditionally (even with
    # HomeEfsFileSystemCreation=Disabled); register their cleanup now, ahead of the stack's,
    # so LIFO runs it after the stack delete and before the VPC/subnet delete. ``state`` is filled
    # in as soon as the domain's physical id is known, even on a path that ends in rollback.
    state: dict = {}

    def _cleanup_nfs_sgs() -> None:
        if state.get("domain_id"):
            _delete_nfs_security_groups(ec2, vpc_id, state["domain_id"])

    ctx.on_cleanup(_cleanup_nfs_sgs)

    stack = ctx.unique_name("sim2real-smdomain-stack-")
    domain_name = ctx.unique_name("sim2real-smdomain-")
    user_profile_name = ctx.unique_name("sim2real-smuser-")
    space_name = ctx.unique_name("sim2real-smspace-")

    stack_id = create_stack(
        ctx, cf, stack,
        _template(domain_name, user_profile_name, space_name, vpc_id, subnet_id, role_arn),
    )
    # One body deadline for create + space + update (1140 s), leaving 600 s for the delete. AWS
    # has kept the domain stack CREATE_IN_PROGRESS past 300 s, so the create alone gets 900 s.
    body_deadline = time.monotonic() + 1140.0
    status = wait_stack(cf, stack_id, timeout_s=900.0)
    state["domain_id"] = _domain_physical_id(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]

    domain_id = out["DomainId"]
    domain_arn = f"arn:{partition}:sagemaker:{ctx.region}:{ctx.account}:domain/{domain_id}"
    assert out["DomainRef"] == domain_id, f"Domain Ref {out['DomainRef']!r} != DomainId {domain_id!r}"
    assert out["DomainArn"] == domain_arn, f"Domain GetAtt Arn {out['DomainArn']!r} != {domain_arn!r}"

    # Ref against an independent read (ListDomains by the declared name), never a read by the Ref.
    domains = paginate(sm, "list_domains", "Domains")
    matches = [d for d in domains if d["DomainName"] == domain_name]
    assert [m["DomainId"] for m in matches] == [domain_id], (
        f"ListDomains by name {domain_name!r} found {matches!r}, expected DomainId {domain_id!r}"
    )

    domain = sm.describe_domain(DomainId=domain_id)
    assert domain["Status"] == "InService", f"domain status {domain['Status']!r}, expected InService"
    got_domain = {
        "AuthMode": domain["AuthMode"],
        "DomainName": domain["DomainName"],
        "VpcId": domain["VpcId"],
        "SubnetIds": domain["SubnetIds"],
        "ExecutionRole": domain["DefaultUserSettings"]["ExecutionRole"],
        "SpaceExecutionRole": domain["DefaultSpaceSettings"]["ExecutionRole"],
        "HomeEfsFileSystemCreation": domain["HomeEfsFileSystemCreation"],
        "DomainArn": domain["DomainArn"],
    }
    want_domain = {
        "AuthMode": "IAM", "DomainName": domain_name, "VpcId": vpc_id,
        "SubnetIds": [subnet_id], "ExecutionRole": role_arn, "SpaceExecutionRole": role_arn,
        "HomeEfsFileSystemCreation": "Disabled", "DomainArn": domain_arn,
    }
    assert got_domain == want_domain, f"describe_domain read {got_domain!r}, expected {want_domain!r}"

    # UserProfile: Ref is the registry's composite primary identifier UserProfileName|DomainId.
    up_ref_want = f"{user_profile_name}|{domain_id}"
    assert out["UserProfileRef"] == up_ref_want, (
        f"UserProfile Ref {out['UserProfileRef']!r} != {up_ref_want!r}"
    )
    up_arn = (f"arn:{partition}:sagemaker:{ctx.region}:{ctx.account}:"
              f"user-profile/{domain_id}/{user_profile_name}")
    assert out["UserProfileArn"] == up_arn, f"UserProfile GetAtt {out['UserProfileArn']!r}"
    profiles = paginate(sm, "list_user_profiles", "UserProfiles", DomainIdEquals=domain_id)
    up_matches = [p for p in profiles if p["UserProfileName"] == user_profile_name]
    assert len(up_matches) == 1, f"ListUserProfiles(DomainIdEquals={domain_id!r}) found {up_matches!r}"
    up = sm.describe_user_profile(DomainId=domain_id, UserProfileName=user_profile_name)
    assert (up["DomainId"], up["UserProfileName"], up["UserProfileArn"]) == (
        domain_id, user_profile_name, up_arn
    ), f"describe_user_profile read {up!r}"
    assert up["Status"] == "InService", f"user profile status {up['Status']!r}, expected InService"

    # Space: Ref is DomainId|SpaceName.
    space_ref_want = f"{domain_id}|{space_name}"
    assert out["SpaceRef"] == space_ref_want, f"Space Ref {out['SpaceRef']!r} != {space_ref_want!r}"
    space_arn = f"arn:{partition}:sagemaker:{ctx.region}:{ctx.account}:space/{domain_id}/{space_name}"
    assert out["SpaceArn"] == space_arn, f"Space GetAtt Arn {out['SpaceArn']!r} != {space_arn!r}"
    spaces = paginate(sm, "list_spaces", "Spaces", DomainIdEquals=domain_id,
                      SpaceNameContains=space_name)
    space_matches = [s for s in spaces if s["SpaceName"] == space_name]
    assert len(space_matches) == 1, f"ListSpaces(DomainIdEquals={domain_id!r}) found {space_matches!r}"
    space_status = _poll_until(
        lambda: sm.describe_space(DomainId=domain_id, SpaceName=space_name)["Status"], _SM_TERMINAL,
        timeout_s=min(300.0, body_deadline - time.monotonic()),
    )
    assert space_status == "InService", f"space status {space_status!r}, expected InService"
    space = sm.describe_space(DomainId=domain_id, SpaceName=space_name)
    assert (space["DomainId"], space["SpaceName"], space["SpaceArn"]) == (
        domain_id, space_name, space_arn
    ), f"describe_space read {space!r}"

    # The propagated stack tag on each of the three resources.
    for arn in (domain_arn, up_arn, space_arn):
        got_tags = _own_tags(sm, arn)
        assert got_tags == {"sim2real": stack}, f"{arn} tags {got_tags!r}"
    domain_created = domain["CreationTime"]

    # Children before the domain: an update dropping the profile and space removes both while
    # the same domain (CreationTime) still answers.
    template = _template(domain_name, user_profile_name, space_name, vpc_id, subnet_id, role_arn,
                         children=False)
    cf.update_stack(StackName=stack_id, TemplateBody=template)
    status = wait_stack(cf, stack_id, timeout_s=max(body_deadline - time.monotonic(), 60.0))
    assert status == "UPDATE_COMPLETE", f"child-dropping update ended {status!r}"
    up_gone = _not_found(partition, ctx.region, ctx.account,
                         ("UserProfile", f"user-profile/{domain_id}/{user_profile_name}"))
    expect_error(
        lambda: sm.describe_user_profile(DomainId=domain_id, UserProfileName=user_profile_name),
        *up_gone,
    )
    space_gone = _not_found(partition, ctx.region, ctx.account,
                            ("Space", f"space/{domain_id}/{space_name}"))
    expect_error(lambda: sm.describe_space(DomainId=domain_id, SpaceName=space_name), *space_gone)
    still = sm.describe_domain(DomainId=domain_id)
    assert (still["CreationTime"], still["Status"]) == (domain_created, "InService"), (
        f"domain after the update reads {still['CreationTime']!r}, {still['Status']!r}"
    )

    delete_stack(cf, stack_id)
    _delete_nfs_security_groups(ec2, vpc_id, domain_id)
    domain_gone = _not_found(partition, ctx.region, ctx.account, ("Domain", f"domain/{domain_id}"))
    expect_error(lambda: sm.describe_domain(DomainId=domain_id), *domain_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
