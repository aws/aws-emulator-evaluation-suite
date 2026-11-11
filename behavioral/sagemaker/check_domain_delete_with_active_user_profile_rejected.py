"""domain-delete-with-active-user-profile-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "domain-delete-with-active-user-profile-rejected"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDomain is rejected while a UserProfile still exists under it; verifies the exact
    error, that the domain and profile are left intact, and that the normal
    delete-profile-then-domain path still works (positive control) in the same file."""
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")

    role_arn = _create_execution_role(ctx, iam)
    vpc_id, subnet_id = _default_vpc_and_subnet(ec2, ctx=ctx)

    domain_name = ctx.unique_name("sim2real-sm-domain-neg-")

    def _create_domain():
        return sm.create_domain(
            DomainName=domain_name,
            AuthMode="IAM",
            DefaultUserSettings={"ExecutionRole": role_arn},
            VpcId=vpc_id,
            SubnetIds=[subnet_id],
            Tags=[{"Key": "sim2real", "Value": domain_name}],
        )

    created = _retry_role_propagation(_create_domain)
    domain_id = created["DomainArn"].rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda: _delete_domain_if_present(ctx, domain_id))

    domain_described = _poll_until(
        lambda: sm.describe_domain(DomainId=domain_id),
        lambda r: r["Status"] in ("InService", "Failed"),
        timeout_s=1200.0,
        interval_s=20.0,
    )
    assert domain_described["Status"] == "InService", (
        f"expected domain {domain_id} InService, got {domain_described['Status']} "
        f"({domain_described.get('FailureReason')})"
    )

    profile_name = ctx.unique_name("sim2real-sm-userprofile-")
    sm.create_user_profile(
        DomainId=domain_id,
        UserProfileName=profile_name,
        Tags=[{"Key": "sim2real", "Value": profile_name}],
    )
    ctx.on_cleanup(lambda: _delete_user_profile_if_present(ctx, domain_id, profile_name))

    profile_described = _poll_until(
        lambda: sm.describe_user_profile(DomainId=domain_id, UserProfileName=profile_name),
        lambda r: r["Status"] in ("InService", "Failed"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert profile_described["Status"] == "InService", (
        f"expected profile {profile_name} InService, got {profile_described['Status']} "
        f"({profile_described.get('FailureReason')})"
    )

    # Break exactly one thing: try to delete the domain while a user profile still exists.
    code, message = _error(
        lambda: sm.delete_domain(DomainId=domain_id),
        "expected DeleteDomain to be rejected while a UserProfile still exists",
    )
    assert code == "ResourceInUse", f"expected ResourceInUse, got {code}"
    expected = (
        f"Unable to delete Domain [arn:aws:sagemaker:{ctx.region}:{ctx.account}:domain/{domain_id}] "
        f"because UserProfile(s) are associated with it."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: domain and profile are both still there.
    domain_after = sm.describe_domain(DomainId=domain_id)["Status"]
    assert domain_after == "InService", f"expected domain still InService, got {domain_after}"
    profile_after = sm.describe_user_profile(DomainId=domain_id, UserProfileName=profile_name)["Status"]
    assert profile_after == "InService", f"expected profile still InService, got {profile_after}"

    # Positive control: delete the user profile first, then the domain succeeds.
    sm.delete_user_profile(DomainId=domain_id, UserProfileName=profile_name)
    profile_code, profile_message = _refusal_eventually(
        lambda: sm.describe_user_profile(DomainId=domain_id, UserProfileName=profile_name),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert profile_code == "ResourceNotFound", f"expected profile gone (ResourceNotFound), got {profile_code}"
    expected = (
        f"UserProfile [arn:aws:sagemaker:{ctx.region}:{ctx.account}:user-profile/{domain_id}/{profile_name}] "
        f"does not exist."
    )
    assert profile_message == expected, f"expected message {expected!r}, got {profile_message!r}"
    sm.delete_domain(DomainId=domain_id)
    gone_code, gone_message = _refusal_eventually(
        lambda: sm.describe_domain(DomainId=domain_id), timeout_s=1200.0, interval_s=20.0
    )
    assert gone_code == "ResourceNotFound", f"expected domain gone (ResourceNotFound), got {gone_code}"
    expected = f"Domain [arn:aws:sagemaker:{ctx.region}:{ctx.account}:domain/{domain_id}] does not exist."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"


def _delete_domain_if_present(ctx, domain_id: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_domain(DomainId=domain_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _delete_user_profile_if_present(ctx, domain_id: str, profile_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_user_profile(DomainId=domain_id, UserProfileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn, expectation: str):
    """Call fn(), which must be rejected; return its (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        e = err.response["Error"]
        return e["Code"], e.get("Message")
    raise AssertionError(f"{expectation}, but it succeeded and returned {result!r}")


def _refusal_eventually(fn, *, timeout_s, interval_s):
    """Poll fn() until it is refused; return the refusal's (code, message). A call that still
    SUCCEEDS at the deadline raises: the deleted resource must stop being describable."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as err:
            e = err.response["Error"]
            return e["Code"], e.get("Message")
        time.sleep(interval_s)
    raise AssertionError(
        f"expected the call to be rejected within {timeout_s}s, but it still SUCCEEDED and "
        f"returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _default_vpc_and_subnet(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
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
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )
    role_arn = role["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    from botocore.exceptions import ClientError

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
