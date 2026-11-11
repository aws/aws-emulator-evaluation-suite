"""domain-create-describe-delete-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "domain-create-describe-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

_POLL_INTERVAL_S = 5.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomain reaches InService and DescribeDomain echoes its name, auth mode, VPC, subnets
    and execution role; DeleteDomain removes it, and a later DescribeDomain and a second delete
    are refused naming the domain ARN."""
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    efs = ctx.client("efs")

    role_arn = _create_execution_role(ctx, iam)
    vpc_id, subnet_id = _shared_vpc_and_subnet(ec2, ctx=ctx)

    domain_name = ctx.unique_name("sim2real-sm-domain-")

    def _create():
        return sm.create_domain(
            DomainName=domain_name,
            AuthMode="IAM",
            DefaultUserSettings={"ExecutionRole": role_arn},
            VpcId=vpc_id,
            SubnetIds=[subnet_id],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    created = _retry_role_propagation(_create)
    domain_id = created["DomainArn"].rsplit("/", 1)[-1]
    home_efs: dict = {}
    # LIFO: the domain is deleted first, then the EFS file system and NFS security groups it left.
    ctx.on_cleanup(lambda: _delete_domain_leftovers(sm, ec2, efs, domain_id, vpc_id, home_efs))
    ctx.on_cleanup(lambda: _delete_domain_if_present(ctx, domain_id))

    def _describe():
        domain = sm.describe_domain(DomainId=domain_id)
        if domain.get("HomeEfsFileSystemId"):
            home_efs["id"] = domain["HomeEfsFileSystemId"]
        return domain

    described = _poll_until(
        _describe,
        lambda r: r["Status"] in ("InService", "Failed"),
        timeout_s=_budget_s(ctx, 1200.0),
        interval_s=_POLL_INTERVAL_S,
        ctx=ctx,
    )
    assert described["Status"] == "InService", f"expected Domain Status=InService, got {described['Status']!r}"
    assert described["DomainName"] == domain_name, (
        f"expected DomainName={domain_name!r}, got {described['DomainName']!r}"
    )
    assert described["AuthMode"] == "IAM", f"expected AuthMode='IAM', got {described['AuthMode']!r}"
    assert described["DefaultUserSettings"]["ExecutionRole"] == role_arn, (
        f"expected DefaultUserSettings.ExecutionRole={role_arn!r}, "
        f"got {described['DefaultUserSettings']['ExecutionRole']!r}"
    )
    network = (described["VpcId"], described["SubnetIds"])
    assert network == (vpc_id, [subnet_id]), (
        f"expected (VpcId, SubnetIds)={(vpc_id, [subnet_id])!r}, got {network!r}"
    )

    sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
    expected = f"Domain [arn:aws:sagemaker:{ctx.region}:{ctx.account}:domain/{domain_id}] does not exist."

    gone_code, gone_message = _refusal_eventually(
        lambda: sm.describe_domain(DomainId=domain_id),
        timeout_s=_budget_s(ctx, 1200.0),
        interval_s=_POLL_INTERVAL_S,
        ctx=ctx,
    )
    assert gone_code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {gone_code!r}"
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    redelete_code, redelete_message = _error(
        lambda: sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
    )
    assert redelete_code == "ResourceNotFound", (
        f"expected a second delete of the same domain to also report ResourceNotFound, got {redelete_code!r}"
    )
    assert redelete_message == expected, f"expected message {expected!r}, got {redelete_message!r}"


def _delete_domain_if_present(ctx, domain_id: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _delete_domain_leftovers(sm, ec2, efs, domain_id, vpc_id, home_efs, timeout_s=1500.0):
    """Wait for the domain to be gone, then delete its home EFS file system if it remains and the
    two NFS security groups SageMaker creates in the VPC, which DeleteDomain leaves behind."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.describe_domain(DomainId=domain_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFound":
                raise
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"domain {domain_id} still exists after {timeout_s}s")
        time.sleep(_POLL_INTERVAL_S)
    if home_efs.get("id"):
        _delete_file_system(efs, home_efs["id"], deadline)
    names = [f"security-group-for-inbound-nfs-{domain_id}", f"security-group-for-outbound-nfs-{domain_id}"]
    groups = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": names}]
    )["SecurityGroups"]
    # The two groups reference each other, so their rules are revoked before either is deleted.
    for group in groups:
        if group.get("IpPermissions"):
            ec2.revoke_security_group_ingress(GroupId=group["GroupId"], IpPermissions=group["IpPermissions"])
        if group.get("IpPermissionsEgress"):
            ec2.revoke_security_group_egress(GroupId=group["GroupId"], IpPermissions=group["IpPermissionsEgress"])
    for group in groups:
        _delete_retrying(lambda gid=group["GroupId"]: ec2.delete_security_group(GroupId=gid), deadline)


def _delete_file_system(efs, fs_id, deadline):
    """Delete the file system and its mount targets unless it is already going; wait until gone."""
    while True:
        try:
            fs = efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "FileSystemNotFound":
                raise
            return
        if fs["LifeCycleState"] == "available":
            for mt in efs.describe_mount_targets(FileSystemId=fs_id)["MountTargets"]:
                if mt["LifeCycleState"] == "available":
                    try:
                        efs.delete_mount_target(MountTargetId=mt["MountTargetId"])
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "MountTargetNotFound":
                            raise
            try:
                efs.delete_file_system(FileSystemId=fs_id)
            except ClientError as exc:
                # A file system refuses deletion until its mount targets are gone.
                if exc.response["Error"]["Code"] not in ("FileSystemInUse", "FileSystemNotFound"):
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"file system {fs_id} still exists ({fs['LifeCycleState']})")
        time.sleep(_POLL_INTERVAL_S)


def _delete_retrying(fn, deadline):
    """Run a security group delete, retrying DependencyViolation (ENIs still leaving) until the
    deadline; a group that is already gone is fine."""
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(_POLL_INTERVAL_S)


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as err:
        e = err.response["Error"]
        return e["Code"], e.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _refusal_eventually(fn, *, timeout_s, interval_s, ctx):
    """Poll fn() until it is refused; return the refusal's (code, message). A call that still
    SUCCEEDS at the deadline raises: the deleted resource must stop being describable."""
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as err:
            e = err.response["Error"]
            return e["Code"], e.get("Message")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError("the deleted domain to stop being describable: the run budget ended first; not graded")
    raise AssertionError(
        f"expected the call to be rejected within {timeout_s}s, but it still SUCCEEDED and "
        f"returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, ctx):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError("the domain to reach a terminal status: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _shared_vpc_and_subnet(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError(f"VPC {vpc_id} has no subnets available to attach a SageMaker Domain")
    return vpc_id, subnets[0]["SubnetId"]


def _create_execution_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_role(RoleName=role_name)))
    inline = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sagemaker:DescribeDomain", "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="domain-read", PolicyDocument=json.dumps(inline))
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="domain-read")
        )
    )
    return role_arn


def _ignore_no_such_entity(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("role propagation retry loop exited without a result")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
