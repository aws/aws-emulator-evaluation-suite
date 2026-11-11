"""app-lifecycle-in-service-to-deleted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "app-lifecycle-in-service-to-deleted"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An App transitions Pending->InService, and after DeleteApp it settles on Status=Deleted:
    unlike most resources, a deleted App stays describable as a terminal Deleted record.
    """
    sm = ctx.client("sagemaker")
    vpc_id, subnet_id = _default_vpc_and_subnet(ctx)
    role_arn = _create_sagemaker_role(ctx, managed_policy_arns=["arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"])
    domain_name = ctx.unique_name("sim2real-domain-")
    profile_name = ctx.unique_name("sim2real-profile-")
    app_name = ctx.unique_name("sim2real-app-")

    domain_id = sm.create_domain(
        DomainName=domain_name,
        AuthMode="IAM",
        DefaultUserSettings={"ExecutionRole": role_arn},
        SubnetIds=[subnet_id],
        VpcId=vpc_id,
        AppNetworkAccessType="PublicInternetOnly",
    )["DomainId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
        )
    )

    domain_status = _poll_until(
        lambda: sm.describe_domain(DomainId=domain_id)["Status"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=1200,
        interval_s=20,
        label="Domain Status=InService",
    )
    assert domain_status == "InService", f"expected Domain Status=InService, got {domain_status}"

    sm.create_user_profile(DomainId=domain_id, UserProfileName=profile_name)
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: sm.delete_user_profile(DomainId=domain_id, UserProfileName=profile_name)
        )
    )
    profile_status = _poll_until(
        lambda: sm.describe_user_profile(DomainId=domain_id, UserProfileName=profile_name)["Status"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=300,
        interval_s=10,
        label="UserProfile Status=InService",
    )
    assert profile_status == "InService", f"expected UserProfile Status=InService, got {profile_status}"

    app_arn = sm.create_app(
        DomainId=domain_id,
        UserProfileName=profile_name,
        AppType="JupyterServer",
        AppName=app_name,
    )["AppArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: sm.delete_app(
                DomainId=domain_id, UserProfileName=profile_name, AppType="JupyterServer", AppName=app_name
            )
        )
    )

    app_status = _poll_until(
        lambda: sm.describe_app(
            DomainId=domain_id, UserProfileName=profile_name, AppType="JupyterServer", AppName=app_name
        )["Status"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=600,
        interval_s=15,
        label="App Status=InService",
    )
    assert app_status == "InService", f"expected App Status=InService, got {app_status}"

    described = sm.describe_app(
        DomainId=domain_id, UserProfileName=profile_name, AppType="JupyterServer", AppName=app_name
    )
    assert described["AppArn"] == app_arn, f"expected AppArn={app_arn!r}, got {described['AppArn']!r}"

    sm.delete_app(DomainId=domain_id, UserProfileName=profile_name, AppType="JupyterServer", AppName=app_name)

    deleted_status = _poll_until(
        lambda: sm.describe_app(
            DomainId=domain_id, UserProfileName=profile_name, AppType="JupyterServer", AppName=app_name
        )["Status"],
        lambda s: s in ("Deleted", "Failed"),
        timeout_s=600,
        interval_s=15,
        label="App Status=Deleted",
    )
    assert deleted_status == "Deleted", f"expected App Status=Deleted, got {deleted_status}"

    # The app record itself must remain describable (not 404) even once deleted.
    final = sm.describe_app(
        DomainId=domain_id, UserProfileName=profile_name, AppType="JupyterServer", AppName=app_name
    )
    assert final["Status"] == "Deleted", f"expected final App Status=Deleted, got {final['Status']!r}"
    assert final["AppArn"] == app_arn, f"expected final AppArn={app_arn!r}, got {final['AppArn']!r}"


# ===== helpers =====
def _ignore_not_found(fn, timeout_s: float = 360.0):
    """Run a teardown delete: retry while a dependent resource is still being released, return
    once the resource is gone, raise everything else."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            error = e.response["Error"]
            if error["Code"] == "ResourceNotFound":
                return
            if error["Code"] == "ValidationException" and "has already been deleted" in error.get("Message", ""):
                return
            if error["Code"] != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, label: str):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {label}, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _default_vpc_and_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to attach a SageMaker Domain")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available for a SageMaker Domain")
    return vpc_id, subnets[0]["SubnetId"]


def _create_sagemaker_role(ctx, managed_policy_arns=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    attached = []
    for policy_arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        attached.append(policy_arn)

    def _cleanup():
        for policy_arn in attached:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(2)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
