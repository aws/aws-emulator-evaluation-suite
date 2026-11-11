"""create-user-profile-duplicate-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-user-profile-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateUserProfile with a UserProfileName that already exists in the domain is refused with ResourceInUse
    and its exact message, and the domain still lists exactly one profile of that name; the first create reaches
    InService.
    """
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host a Domain")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available to host a Domain")
    subnet_id = subnets[0]["SubnetId"]

    role_arn = _create_sagemaker_role(ctx)
    sm = ctx.client("sagemaker")

    domain_name = ctx.unique_name("sim2real-domain-")
    created = _retry_role_propagation(
        lambda: sm.create_domain(
            DomainName=domain_name,
            AuthMode="IAM",
            DefaultUserSettings={"ExecutionRole": role_arn},
            VpcId=vpc_id,
            SubnetIds=[subnet_id],
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
    )
    domain_id = created["DomainArn"].rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda: _delete_domain_when_free(sm, domain_id))
    domain_status = _poll_until(
        lambda: sm.describe_domain(DomainId=domain_id)["Status"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=900,
        interval_s=20,
    )
    assert domain_status == "InService", f"domain never reached InService: {domain_status}"

    profile_name = ctx.unique_name("sim2real-profile-")

    # (c) positive control: the first CreateUserProfile succeeds and reaches
    # InService.
    sm.create_user_profile(
        DomainId=domain_id,
        UserProfileName=profile_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: sm.delete_user_profile(DomainId=domain_id, UserProfileName=profile_name)
        )
    )
    profile_status = _poll_until(
        lambda: sm.describe_user_profile(DomainId=domain_id, UserProfileName=profile_name)[
            "Status"
        ],
        lambda s: s in ("InService", "Failed"),
        timeout_s=300,
        interval_s=10,
    )
    assert profile_status == "InService", f"user profile never reached InService: {profile_status}"

    # Negative: a second CreateUserProfile with the same name in the same domain is
    # rejected.
    code, message = _error(
        lambda: sm.create_user_profile(DomainId=domain_id, UserProfileName=profile_name)
    )
    assert code == "ResourceInUse", f"expected ResourceInUse, got {code}"
    expected = f"A UserProfile with name '{profile_name}' already exists in Domain {domain_id}."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # (b) effect absent: only one profile with this name exists under the domain.
    matches = [
        p
        for p in sm.list_user_profiles(DomainIdEquals=domain_id)["UserProfiles"]
        if p["UserProfileName"] == profile_name
    ]
    assert len(matches) == 1, f"expected exactly one user profile, found {len(matches)}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _delete_domain_when_free(sm, domain_id, timeout_s=600.0):
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


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _retry_role_propagation(fn, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("AccessDeniedException", "ValidationException"):
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-smrole-")
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
