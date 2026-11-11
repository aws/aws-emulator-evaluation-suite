"""create-user-profile-duplicate-name-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-user-profile-duplicate-name-denied"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUserProfile with a name already used in the same domain is rejected with ResourceInUse."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)
    vpc_id, subnet_id = _get_default_vpc_subnet(ctx)

    domain_name = ctx.unique_name("sim2real-behav-dom-")

    def _create_domain():
        return sm.create_domain(
            DomainName=domain_name,
            AuthMode="IAM",
            DefaultUserSettings={"ExecutionRole": role_arn},
            SubnetIds=[subnet_id],
            VpcId=vpc_id,
        )

    domain_resp = _retry_role_propagation(_create_domain)
    domain_id = domain_resp["DomainId"]
    ctx.on_cleanup(lambda: _cleanup_domain(sm, domain_id))
    domain_status = _wait_for_domain_stable(sm, domain_id)
    assert domain_status == "InService", f"expected domain {domain_id} to reach InService, got {domain_status}"

    profile_name = ctx.unique_name("sim2real-behav-profile-")
    sm.create_user_profile(DomainId=domain_id, UserProfileName=profile_name)
    ctx.on_cleanup(lambda: _cleanup_profile(sm, domain_id, profile_name))

    # duplicate create with the exact same name in the same domain must be denied
    code, message = _error(lambda: sm.create_user_profile(DomainId=domain_id, UserProfileName=profile_name))
    assert code == "ResourceInUse", f"expected ResourceInUse for a duplicate profile name, got {code}"
    expected = f"A UserProfile with name '{profile_name}' already exists in Domain {domain_id}."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # effect absent: still exactly one profile with this name in the domain
    profiles = sm.list_user_profiles(DomainIdEquals=domain_id)["UserProfiles"]
    matching = [p for p in profiles if p["UserProfileName"] == profile_name]
    assert len(matching) == 1, f"expected exactly one profile named {profile_name!r}, found {len(matching)}"

    # positive control: a differently-named profile in the same domain succeeds. The
    # terminal read is independent of the CreateUserProfile call that mutated: it goes
    # through ListUserProfiles, not the create response's own echoed fields.
    other_profile_name = ctx.unique_name("sim2real-behav-profile2-")
    sm.create_user_profile(DomainId=domain_id, UserProfileName=other_profile_name)
    ctx.on_cleanup(lambda: _cleanup_profile(sm, domain_id, other_profile_name))
    other_profiles = sm.list_user_profiles(DomainIdEquals=domain_id)["UserProfiles"]
    other_matching = [p for p in other_profiles if p["UserProfileName"] == other_profile_name]
    assert len(other_matching) == 1, (
        f"expected the differently-named profile {other_profile_name!r} to be independently "
        f"listable, found {len(other_matching)}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _cleanup_domain(sm, domain_id, timeout_s=600.0):
    """DeleteDomain refuses with ResourceInUse while a user profile is still deleting; retry
    that refusal until the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(15)


def _cleanup_profile(sm, domain_id, profile_name):
    _wait_for_profile_deletable(sm, domain_id, profile_name)
    try:
        sm.delete_user_profile(DomainId=domain_id, UserProfileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _wait_for_profile_deletable(sm, domain_id, profile_name, timeout_s=180.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = sm.describe_user_profile(DomainId=domain_id, UserProfileName=profile_name)["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFound":
                raise
            return
        if status != "Pending":
            return
        time.sleep(interval_s)


def _wait_for_domain_stable(sm, domain_id, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sm.describe_domain(DomainId=domain_id)["Status"]
        if status != "Pending":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_id} still Pending after {timeout_s}s (last status: {status!r})")


def _retry_role_propagation(fn, timeout_s=60.0, interval_s=5.0):
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
    raise AssertionError(f"execution role never propagated within {timeout_s}s: {last_err}")


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-smrole-")
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
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(1.0)
    return role_arn


def _get_default_vpc_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("selected VPC has no subnets available to provision a SageMaker Domain")
    return vpc_id, subnets[0]["SubnetId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
