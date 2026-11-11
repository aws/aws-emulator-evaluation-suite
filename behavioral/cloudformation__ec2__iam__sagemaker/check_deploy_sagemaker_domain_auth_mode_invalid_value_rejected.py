"""deploy-sagemaker-domain-auth-mode-invalid-value-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sagemaker-domain-auth-mode-invalid-value-rejected"
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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

def _template(domain_name, vpc_id, subnet_id, role_arn, auth_mode):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Domain": {
                "Type": "AWS::SageMaker::Domain",
                "Properties": {
                    "DomainName": domain_name,
                    "AuthMode": auth_mode,
                    "VpcId": vpc_id,
                    "SubnetIds": [subnet_id],
                    "HomeEfsFileSystemCreation": "Disabled",
                    "DefaultUserSettings": {"ExecutionRole": role_arn},
                },
            },
        },
        "Outputs": {"DomainId": {"Value": {"Fn::GetAtt": ["Domain", "DomainId"]}}},
    })


def _vpc_subnet(ctx, ec2, cidr_prefix):
    """A fresh, disposable VPC+subnet (never the account's default VPC)."""
    vpc_id = ec2.create_vpc(
        CidrBlock=f"{cidr_prefix}.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-smauth-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=f"{cidr_prefix}.0.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-smauth-subnet-")}],
        }],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return vpc_id, subnet_id


def _retry_delete(fn, attempts: int = 15, delay: float = 10.0) -> None:
    for i in range(attempts):
        try:
            fn()
            return
        except ClientError:
            if i == attempts - 1:
                raise
            time.sleep(delay)


def _role(ctx, iam, suffix):
    role_name = ctx.unique_name(f"sim2real-smauth-role-{suffix}-")
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
    return role_arn


def _teardown_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_nfs_security_groups(ec2, vpc_id, domain_id, attempts: int = 20, delay: float = 10.0) -> None:
    """A Domain provisions its NFS security-group pair unconditionally, even with EFS creation
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
    """The Domain's PhysicalResourceId if CloudFormation ever created it, else None."""
    try:
        detail = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Domain")
    except ClientError:
        return None
    return detail["StackResourceDetail"].get("PhysicalResourceId")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation SageMaker Domain with an invalid AuthMode fails early validation.

    No domain of that name appears in SageMaker, while the same template with AuthMode IAM deploys.
    """
    cf = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    vpc_id, subnet_id = _vpc_subnet(ctx, ec2, "10.210")
    role_arn = _role(ctx, iam, "good")

    # Negative: the template with an invalid AuthMode, refused before anything is provisioned.
    bad_domain_name = ctx.unique_name("sim2real-smauth-bad-")
    bad_id = create_stack(ctx, cf, ctx.unique_name("sim2real-smauth-badstack-"),
                          _template(bad_domain_name, vpc_id, subnet_id, role_arn, "BADMODE"))
    bad_status = wait_stack(cf, bad_id)
    assert bad_status == "ROLLBACK_COMPLETE", f"rejected stack ended {bad_status!r}"
    rows = validation_rows(cf, bad_id)
    want_rows = [(
        "Domain", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        "BADMODE is not a valid enum value. Supported values: [SSO, IAM]",
        "/Resources/Domain/Properties/AuthMode",
    )]
    assert rows == want_rows, f"validation rows {rows!r}, expected {want_rows!r}"
    # Rollback absence through SageMaker, by the name the domain would have, before any delete.
    domains = [d for d in paginate(sm, "list_domains", "Domains")
               if d["DomainName"] == bad_domain_name]
    assert domains == [], f"the rejected template's domain is listed: {domains!r}"

    # Positive control: the same template, the one property given a VALID value.
    good_state: dict = {}

    def _cleanup_good_nfs_sgs() -> None:
        if good_state.get("domain_id"):
            _delete_nfs_security_groups(ec2, vpc_id, good_state["domain_id"])

    ctx.on_cleanup(_cleanup_good_nfs_sgs)
    good_domain_name = ctx.unique_name("sim2real-smauth-good-")
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-smauth-goodstack-"),
                           _template(good_domain_name, vpc_id, subnet_id, role_arn, "IAM"))
    good_status = wait_stack(cf, good_id)
    good_state["domain_id"] = _domain_physical_id(cf, good_id)
    assert good_status == "CREATE_COMPLETE", f"control stack ended {good_status!r}"
    good_domain_id = stack_outputs(cf, good_id)["DomainId"]
    listed = [d["DomainId"] for d in paginate(sm, "list_domains", "Domains")
              if d["DomainName"] == good_domain_name]
    assert listed == [good_domain_id], f"ListDomains found {listed!r} for {good_domain_name!r}"
    control = sm.describe_domain(DomainId=good_domain_id)
    got = (control["AuthMode"], control["DomainName"], control["VpcId"], control["SubnetIds"],
           control["DefaultUserSettings"]["ExecutionRole"])
    want = ("IAM", good_domain_name, vpc_id, [subnet_id], role_arn)
    assert got == want, f"control domain reads {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
