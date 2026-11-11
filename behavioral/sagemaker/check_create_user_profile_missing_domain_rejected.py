"""create-user-profile-missing-domain-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-user-profile-missing-domain-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]

_POLL_INTERVAL_S = 2.0
_TEARDOWN_POLL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUserProfile against a well-formed but nonexistent DomainId is rejected naming the
    domain and creates nothing; the same call succeeds against a real Domain once InService."""
    sm = ctx.client("sagemaker")
    ec2 = ctx.client("ec2")

    # The positive control's Domain lives in a VPC and subnet this check creates and deletes.
    vpc_id, subnet_id = _create_vpc_and_subnet(ctx, ec2)

    role_arn = _create_sagemaker_exec_role(ctx)

    # Matches the DomainId pattern (^d-...$) but names no Domain.
    fake_domain_id = "d-" + "sim2realxx"
    bad_profile_name = ctx.unique_name("sim2real-sm-up-bad-")
    code, message = _error(
        lambda: sm.create_user_profile(
            DomainId=fake_domain_id, UserProfileName=bad_profile_name
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == f"Domain [{fake_domain_id}] does not exist", (
        f"expected the validation error to name the (nonexistent) domain — i.e. a "
        f"real existence check, not a generic malformed-input rejection — got: {message!r}"
    )

    not_found_code, not_found_message = _error(
        lambda: sm.describe_user_profile(
            DomainId=fake_domain_id, UserProfileName=bad_profile_name
        )
    )
    assert not_found_code == "ResourceNotFound", (
        f"expected DescribeUserProfile against the nonexistent domain to fail, "
        f"got {not_found_code}"
    )
    expected_absent = (
        f"UserProfile [arn:aws:sagemaker:{ctx.region}:{ctx.account}:user-profile/"
        f"{fake_domain_id}/{bad_profile_name}] does not exist."
    )
    assert not_found_message == expected_absent, (
        f"expected {expected_absent!r}, got {not_found_message!r}"
    )


    # A Domain still Pending rejects CreateUserProfile ("... is not in InService"), so the
    # positive control waits for InService.
    domain_name = ctx.unique_name("sim2real-sm-domain-")
    domain_resp = None
    last_domain_error = None
    domain_deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        try:
            domain_resp = sm.create_domain(
                DomainName=domain_name,
                AuthMode="IAM",
                DefaultUserSettings={"ExecutionRole": role_arn},
                SubnetIds=[subnet_id],
                VpcId=vpc_id,
                Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
            )
            break
        except ClientError as exc:
            last_domain_error = exc
            if time.monotonic() >= domain_deadline:
                break
            time.sleep(_POLL_INTERVAL_S)
    if domain_resp is None:
        if _budget_spent(ctx):
            raise TimeoutError("CreateDomain to accept the execution role: the run budget ended first; not graded")
        raise AssertionError(
            f"CreateDomain did not succeed within the check's time budget while waiting "
            f"for the just-created execution role to become assumable by SageMaker "
            f"(last error: {last_domain_error})."
        )
    domain_id = domain_resp["DomainId"]
    # LIFO: the Domain is deleted first, then the NFS security groups SageMaker created for it.
    ctx.on_cleanup(lambda: _delete_domain_nfs_security_groups(sm, ec2, domain_id, vpc_id))
    ctx.on_cleanup(lambda: _delete_domain_when_free(sm, domain_id))

    domain_status = _wait_domain_status(
        sm, domain_id, {"InService", "Failed"}, timeout_s=_budget_s(ctx, 600.0), ctx=ctx
    )
    assert domain_status == "InService", (
        f"domain {domain_id} never reached InService (ended at {domain_status}); cannot "
        f"exercise the positive control without a usable Domain."
    )

    good_profile_name = ctx.unique_name("sim2real-sm-up-good-")
    resp = None
    last_error = None
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            resp = sm.create_user_profile(
                DomainId=domain_id,
                UserProfileName=good_profile_name,
                Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
            )
            break
        except ClientError as exc:
            last_error = exc
            if time.monotonic() >= deadline:
                break
            time.sleep(_POLL_INTERVAL_S)
    if resp is None:
        if _budget_spent(ctx):
            raise TimeoutError("the Domain to accept CreateUserProfile: the run budget ended first; not graded")
        raise AssertionError(
            f"the Domain did not accept CreateUserProfile within the check's time "
            f"budget (last error: {last_error}); Domain provisioning can take several "
            f"minutes, longer than this check can wait."
        )
    assert resp["UserProfileArn"].endswith(f"user-profile/{domain_id}/{good_profile_name}")


    def _delete_profile_and_wait():
        # DeleteUserProfile refuses while the profile is still provisioning; retry it.
        deadline1 = time.monotonic() + 300
        while True:
            try:
                sm.delete_user_profile(DomainId=domain_id, UserProfileName=good_profile_name)
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFound":
                    return
                if time.monotonic() >= deadline1:
                    raise
                time.sleep(_TEARDOWN_POLL_S)
        deadline2 = time.monotonic() + 300
        last = None
        while time.monotonic() < deadline2:
            try:
                last = sm.describe_user_profile(
                    DomainId=domain_id, UserProfileName=good_profile_name).get("Status")
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFound":
                    return
                last = exc
            time.sleep(_TEARDOWN_POLL_S)
        raise RuntimeError(f"user profile {good_profile_name} was not deleted: {last!r}")


    ctx.on_cleanup(_delete_profile_and_wait)

    described = sm.describe_user_profile(
        DomainId=domain_id, UserProfileName=good_profile_name
    )
    assert described["UserProfileName"] == good_profile_name

    # Teardown in the body, so the slow Domain deletion is not bound by the cleanup budget;
    # the registered cleanups tolerate what is already gone.
    _delete_profile_and_wait()
    _delete_domain_when_free(sm, domain_id)
    _delete_domain_nfs_security_groups(sm, ec2, domain_id, vpc_id)


def _delete_domain_when_free(sm, domain_id, timeout_s=600):
    """DeleteDomain refuses with ResourceInUse while a user profile is still deleting; retry
    that refusal until the deadline. A Domain that is already gone is fine."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(_TEARDOWN_POLL_S)


def _delete_domain_nfs_security_groups(sm, ec2, domain_id, vpc_id, timeout_s=600):
    """Wait for the Domain to be gone, then delete the two NFS security groups SageMaker
    creates for it in the VPC (DeleteDomain leaves them). They reference each other, so their
    rules are revoked first; a delete is retried while the Domain's EFS mount targets still
    hold the group (DependencyViolation)."""
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
        time.sleep(_TEARDOWN_POLL_S)
    names = [f"security-group-for-inbound-nfs-{domain_id}", f"security-group-for-outbound-nfs-{domain_id}"]
    groups = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": names}]
    )["SecurityGroups"]
    for group in groups:
        if group.get("IpPermissions"):
            ec2.revoke_security_group_ingress(GroupId=group["GroupId"], IpPermissions=group["IpPermissions"])
        if group.get("IpPermissionsEgress"):
            ec2.revoke_security_group_egress(GroupId=group["GroupId"], IpPermissions=group["IpPermissionsEgress"])
    for group in groups:
        _delete_retrying(lambda gid=group["GroupId"]: ec2.delete_security_group(GroupId=gid), deadline)


def _create_vpc_and_subnet(ctx, ec2):
    vpc_id = ec2.create_vpc(
        CidrBlock="10.196.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_retrying(lambda: ec2.delete_vpc(VpcId=vpc_id), time.monotonic() + 600))
    zone = next(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
    )
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.196.0.0/24",
        AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-subnet-")}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_retrying(lambda: ec2.delete_subnet(SubnetId=subnet_id), time.monotonic() + 600))
    return vpc_id, subnet_id


def _delete_retrying(fn, deadline, interval_s=15.0):
    """Run a network delete, retrying DependencyViolation (ENIs still leaving) until the
    deadline; a resource that is already gone is fine."""
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_domain_status(sm, domain_id, terminal_statuses, timeout_s, ctx=None):
    deadline = time.monotonic() + timeout_s
    while True:
        status = sm.describe_domain(DomainId=domain_id)["Status"]
        if status in terminal_statuses:
            return status
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"domain {domain_id} to reach {terminal_statuses}: the run budget ended first; not graded")
            raise AssertionError(
                f"domain {domain_id} did not reach {terminal_statuses} within {timeout_s:.0f}s "
                f"(last status={status})"
            )
        time.sleep(_POLL_INTERVAL_S)


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_sagemaker_exec_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sagemaker.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    )
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
