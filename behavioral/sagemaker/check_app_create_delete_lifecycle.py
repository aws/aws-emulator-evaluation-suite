"""app-create-delete-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "app-create-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]
_TAGS = [{"Key": "sim2real", "Value": CHECK}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """App moves Pending -> InService -> (delete) -> Deleted, and a re-delete is rejected with
    ValidationException "has already been deleted" rather than ResourceNotFound, because the App
    record stays describable for 24h after deletion."""
    sm = ctx.client("sagemaker")

    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    role_arn = _create_sagemaker_execution_role(ctx)

    domain_name = ctx.unique_name("sim2real-domain-")
    resp = sm.create_domain(
        DomainName=domain_name,
        AuthMode="IAM",
        DefaultUserSettings={"ExecutionRole": role_arn},
        SubnetIds=subnet_ids,
        VpcId=vpc_id,
        Tags=_TAGS,
    )
    domain_id = resp["DomainId"]
    ctx.on_cleanup(lambda: _delete_domain_safe(sm, domain_id))

    _poll_until(
        lambda: sm.describe_domain(DomainId=domain_id)["Status"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=900.0,
        interval_s=15.0,
    )

    profile_name = ctx.unique_name("sim2real-profile-")
    sm.create_user_profile(DomainId=domain_id, UserProfileName=profile_name, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_user_profile_safe(sm, domain_id, profile_name))

    _poll_until(
        lambda: sm.describe_user_profile(DomainId=domain_id, UserProfileName=profile_name)["Status"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=300.0,
        interval_s=10.0,
    )

    app_name = ctx.unique_name("sim2real-app-")
    sm.create_app(
        DomainId=domain_id,
        AppType="JupyterServer",
        AppName=app_name,
        UserProfileName=profile_name,
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_app_safe(sm, domain_id, app_name, profile_name))

    def _describe_status():
        return sm.describe_app(
            DomainId=domain_id, AppType="JupyterServer", AppName=app_name, UserProfileName=profile_name
        )["Status"]

    status = _poll_until(_describe_status, lambda s: s in ("InService", "Failed"), timeout_s=600.0, interval_s=15.0)
    assert status == "InService", f"app did not reach InService, status={status}"

    sm.delete_app(DomainId=domain_id, AppType="JupyterServer", AppName=app_name, UserProfileName=profile_name)

    status2 = _poll_until(_describe_status, lambda s: s == "Deleted", timeout_s=600.0, interval_s=15.0)
    assert status2 == "Deleted", f"app did not settle on Deleted after delete, status={status2}"

    redelete_error = _error(
        lambda: sm.delete_app(
            DomainId=domain_id, AppType="JupyterServer", AppName=app_name, UserProfileName=profile_name
        )
    )
    # Once an App has settled on Status=Deleted, a further DeleteApp is
    # rejected with ValidationException (not ResourceNotFound -- the App record still exists,
    # visible via DescribeApp/ListApps for 24h after deletion) and the message names the App and
    # says it "has already been deleted", which is what separates this from an unrelated
    # malformed-request ValidationException.
    assert redelete_error["Code"] == "ValidationException", (
        f"expected ValidationException on redelete of a Deleted app, got {redelete_error!r}"
    )
    expected_message = (
        f"App [{app_name}] has already been deleted. For tracking purposes, apps are available in the "
        "ListApps API results for only 24 hours after deletion."
    )
    assert redelete_error["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {redelete_error.get('Message')!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore error dict (Code + Message). An unexpected success raises,
    because accepting a call AWS refuses is a distinct failure from an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


def _default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host a SageMaker Studio domain")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to host a SageMaker Studio domain")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    return vpc_id, subnet_ids


def _create_sagemaker_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-exec-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_TAGS)
    role_arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        from botocore.exceptions import ClientError

        for call in (
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                call()
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_cleanup)
    # IAM role propagation can lag briefly; poll for visibility before using it.
    _poll_until(lambda: iam.get_role(RoleName=role_name)["Role"]["Arn"], lambda a: a == role_arn, timeout_s=30.0, interval_s=2.0)
    return role_arn


def _delete_app_safe(sm, domain_id, app_name, profile_name) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.delete_app(DomainId=domain_id, AppType="JupyterServer", AppName=app_name, UserProfileName=profile_name)
    except ClientError as e:
        error = e.response["Error"]
        if error["Code"] == "ResourceNotFound":
            return
        if error["Code"] != "ValidationException" or "has already been deleted" not in error.get("Message", ""):
            raise


def _delete_user_profile_safe(sm, domain_id, profile_name) -> None:
    """Delete the profile and wait until it is gone: DeleteDomain refuses a domain that still has
    a user profile, so returning while the profile is Deleting would leak the domain."""
    from botocore.exceptions import ClientError

    def _status():
        try:
            return sm.describe_user_profile(DomainId=domain_id, UserProfileName=profile_name)["Status"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFound":
                return "Gone"
            raise

    def _delete_once():
        status = _status()
        if status == "Gone":
            return True
        if status != "Deleting":
            try:
                sm.delete_user_profile(DomainId=domain_id, UserProfileName=profile_name)
            except ClientError as e:
                if e.response["Error"]["Code"] not in ("ResourceNotFound", "ResourceInUse"):
                    raise
        return False

    _poll_until(_delete_once, lambda done: done, timeout_s=300.0, interval_s=10.0)
    _poll_until(_status, lambda s: s == "Gone", timeout_s=600.0, interval_s=10.0)


def _delete_domain_safe(sm, domain_id) -> None:
    """Delete the domain (retrying while its user profile is still being torn down) and wait
    until it is gone."""
    from botocore.exceptions import ClientError

    def _status():
        try:
            return sm.describe_domain(DomainId=domain_id)["Status"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFound":
                return "Gone"
            raise

    def _delete_once():
        status = _status()
        if status in ("Gone", "Deleting"):
            return True
        try:
            sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFound":
                return True
            if e.response["Error"]["Code"] in ("ResourceInUse", "ValidationException"):
                return False
            raise

    _poll_until(_delete_once, lambda done: done, timeout_s=600.0, interval_s=15.0)
    _poll_until(_status, lambda s: s == "Gone", timeout_s=900.0, interval_s=15.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
