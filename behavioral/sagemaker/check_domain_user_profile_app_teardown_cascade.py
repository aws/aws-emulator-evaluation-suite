"""domain-user-profile-app-teardown-cascade."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "domain-user-profile-app-teardown-cascade"
GROUP = "e2e"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With Domain and UserProfile InService, CreateApp(AppType="KernelGateway") is refused as a
    deprecated AppType and ListApps shows no App; deleting the UserProfile, then the Domain,
    leaves each ResourceNotFound."""
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")

    role_arn = _create_execution_role(ctx, iam)
    vpc_id, subnet_id = _default_vpc_and_subnet(ec2, ctx=ctx)

    domain_name = ctx.unique_name("sim2real-sm-domain-")
    instance_type = "ml.t3.medium"

    def _create_domain():
        return sm.create_domain(
            DomainName=domain_name,
            AuthMode="IAM",
            DefaultUserSettings={
                "ExecutionRole": role_arn,
                "KernelGatewayAppSettings": {
                    "DefaultResourceSpec": {"InstanceType": instance_type},
                },
            },
            VpcId=vpc_id,
            SubnetIds=[subnet_id],
            Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
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
    assert domain_described["Status"] == "InService", domain_described.get("FailureReason")

    profile_name = ctx.unique_name("sim2real-sm-profile-")
    sm.create_user_profile(
        DomainId=domain_id,
        UserProfileName=profile_name,
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: _delete_user_profile_if_present(ctx, domain_id, profile_name))

    profile_described = _poll_until(
        lambda: sm.describe_user_profile(DomainId=domain_id, UserProfileName=profile_name),
        lambda r: r["Status"] in ("InService", "Failed"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert profile_described["Status"] == "InService", (
        f"expected InService, got {profile_described['Status']!r} "
        f"({profile_described.get('FailureReason')})"
    )

    app_name = ctx.unique_name("sim2real-sm-app-")

    # Withdrawal is the contract: real AWS rejects every KernelGateway App unconditionally, so
    # "no ResourceSpec here, the App must inherit InstanceType from the Domain default" cannot
    # be exercised through a live App. Assert the specific refusal instead of a live app.
    def _create_kernel_gateway_app():
        sm.create_app(
            DomainId=domain_id,
            UserProfileName=profile_name,
            AppType="KernelGateway",
            AppName=app_name,
            Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
        )

    try:
        _create_kernel_gateway_app()
    except Exception as err:  # noqa: BLE001 -- classified immediately below, never swallowed
        from botocore.exceptions import ClientError

        assert isinstance(err, ClientError), f"expected a ClientError, got {err!r}"
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")
        assert code == "ValidationException", (
            f"expected ValidationException for a deprecated AppType, got {code!r}: {message!r}"
        )
        expected = "Invalid AppType [KernelGateway]. This AppType has been deprecated."
        assert message == expected, (
            f"expected the message to name KernelGateway as deprecated (not merely malformed "
            f"or out-of-range): expected {expected!r}, got {message!r}"
        )
    else:
        ctx.on_cleanup(lambda: _delete_app_if_present(ctx, domain_id, profile_name, app_name))
        raise AssertionError(
            "CreateApp(AppType=KernelGateway) succeeded -- real AWS has deprecated this AppType "
            "and this check asserts the refusal; a target that accepts it has regressed "
            "relative to the AWS behaviour recorded in this oracle"
        )

    # Effect absent: no App was ever created under this UserProfile.
    apps = sm.list_apps(DomainIdEquals=domain_id, UserProfileNameEquals=profile_name)["Apps"]
    app_names = [a["AppName"] for a in apps]
    assert app_name not in app_names, (
        f"expected no App named {app_name!r} after the rejected CreateApp, found it in {app_names!r}"
    )

    # ----- teardown cascade (Domain -> UserProfile only; no App was ever created) -----
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

    # DeleteDomain is documented to fail with ResourceInUse while any App/UserProfile is
    # still attached, so a clean success here IS the "no orphans left under the domain"
    # assertion, not merely a describe-returns-404 check.
    sm.delete_domain(DomainId=domain_id)
    gone_code, gone_message = _refusal_eventually(
        lambda: sm.describe_domain(DomainId=domain_id), timeout_s=1200.0, interval_s=20.0
    )
    assert gone_code == "ResourceNotFound", f"expected domain gone (ResourceNotFound), got {gone_code}"
    expected = f"Domain [arn:aws:sagemaker:{ctx.region}:{ctx.account}:domain/{domain_id}] does not exist."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"


# ===== helpers =====
def _delete_domain_if_present(ctx, domain_id: str) -> None:
    """DeleteDomain is refused with ResourceInUse while a UserProfile is still deleting: retry it."""
    from botocore.exceptions import ClientError

    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + 600.0
    while True:
        try:
            sm.delete_domain(DomainId=domain_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFound":
                return
            if code != "ResourceInUse":
                raise
            if sm.describe_domain(DomainId=domain_id)["Status"] == "Deleting":
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_user_profile_if_present(ctx, domain_id: str, profile_name: str) -> None:
    from botocore.exceptions import ClientError

    sm = ctx.client("sagemaker")
    try:
        sm.delete_user_profile(DomainId=domain_id, UserProfileName=profile_name)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        if code == "ResourceNotFound":
            return
        if code != "ResourceInUse":  # already deleting
            raise
    # The domain teardown that follows needs the profile gone.
    deadline = time.monotonic() + 300.0
    while True:
        try:
            sm.describe_user_profile(DomainId=domain_id, UserProfileName=profile_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"user profile {profile_name} still describable after 300s")
        time.sleep(2)


def _delete_app_if_present(ctx, domain_id: str, profile_name: str, app_name: str) -> None:
    from botocore.exceptions import ClientError

    sm = ctx.client("sagemaker")
    try:
        sm.delete_app(
            DomainId=domain_id,
            UserProfileName=profile_name,
            AppType="KernelGateway",
            AppName=app_name,
        )
    except ClientError as err:
        error = err.response["Error"]
        if error["Code"] == "ResourceNotFound":
            return
        if error["Code"] != "ValidationException" or "already" not in error.get("Message", ""):
            raise


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
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    )

    def _cleanup():
        from botocore.exceptions import ClientError

        for delete in (
            lambda: iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
            ),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                delete()
            except ClientError as err:
                if err.response["Error"]["Code"] != "NoSuchEntity":
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
