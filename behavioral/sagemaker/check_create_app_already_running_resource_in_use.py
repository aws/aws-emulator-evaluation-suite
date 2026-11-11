"""create-app-already-running-resource-in-use."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-app-already-running-resource-in-use"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApp for a profile already running the same AppType/AppName is ResourceInUse and leaves
    the existing app untouched; the same AppType/AppName under a different profile in the domain
    succeeds, so the conflict is scoped to the exact DomainId/UserProfile/AppType/AppName tuple.
    """
    sm = ctx.client("sagemaker")
    ec2 = ctx.client("ec2")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host a SageMaker Studio domain")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to host a SageMaker Studio domain")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]

    role_arn = _create_execution_role(ctx)

    domain_name = ctx.unique_name("sim2real-domain-")
    domain_resp = _retry_role_propagation(
        lambda: sm.create_domain(
            DomainName=domain_name,
            AuthMode="IAM",
            DefaultUserSettings={"ExecutionRole": role_arn},
            SubnetIds=subnet_ids,
            VpcId=vpc_id,
            AppNetworkAccessType="PublicInternetOnly",
        )
    )
    domain_id = domain_resp["DomainId"]
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
        )
    )
    _poll_until(
        lambda: sm.describe_domain(DomainId=domain_id)["Status"],
        lambda status: status == "InService",
        timeout_s=900,
        interval_s=15,
        description="domain to become InService",
    )

    profile1 = ctx.unique_name("sim2real-user-")
    profile2 = ctx.unique_name("sim2real-user-")
    for profile in (profile1, profile2):
        sm.create_user_profile(DomainId=domain_id, UserProfileName=profile)
        ctx.on_cleanup(
            lambda p=profile: _delete_and_wait(
                lambda: sm.delete_user_profile(DomainId=domain_id, UserProfileName=p),
                lambda: sm.describe_user_profile(DomainId=domain_id, UserProfileName=p),
            )
        )
        _poll_until(
            lambda p=profile: sm.describe_user_profile(DomainId=domain_id, UserProfileName=p)["Status"],
            lambda status: status == "InService",
            timeout_s=180,
            interval_s=10,
            description=f"user profile {profile} to become InService",
        )

    app_name = ctx.unique_name("sim2real-app-")

    sm.create_app(DomainId=domain_id, UserProfileName=profile1, AppType="JupyterServer", AppName=app_name)
    ctx.on_cleanup(
        lambda: _delete_and_wait(
            lambda: sm.delete_app(
                DomainId=domain_id, UserProfileName=profile1, AppType="JupyterServer", AppName=app_name
            ),
            lambda: sm.describe_app(
                DomainId=domain_id, UserProfileName=profile1, AppType="JupyterServer", AppName=app_name
            ),
        )
    )

    _poll_until(
        lambda: sm.describe_app(
            DomainId=domain_id, UserProfileName=profile1, AppType="JupyterServer", AppName=app_name
        )["Status"],
        lambda status: status in ("InService", "Failed"),
        timeout_s=900,
        interval_s=15,
        description=f"app {app_name} to leave Pending",
    )
    app_status = sm.describe_app(
        DomainId=domain_id, UserProfileName=profile1, AppType="JupyterServer", AppName=app_name
    )["Status"]
    assert app_status == "InService", f"expected the first app to reach InService, got {app_status!r}"

    # Break exactly one thing: create the same AppType/AppName again under profile1.
    code, message = _error(
        lambda: sm.create_app(
            DomainId=domain_id, UserProfileName=profile1, AppType="JupyterServer", AppName=app_name
        )
    )
    assert code == "ResourceInUse", code
    app_arn = (
        f"arn:aws:sagemaker:{ctx.region}:{ctx.account}:app/{domain_id}/{profile1}/JupyterServer/{app_name}"
    )
    expected_message = (
        f"App [{app_arn}] is currently in [InService] status. "
        "To restart the App, wait until it is in Deleted or Failed status."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: still exactly one app of that name/type for profile1.
    apps = sm.list_apps(DomainIdEquals=domain_id, UserProfileNameEquals=profile1)["Apps"]
    matching = [a for a in apps if a["AppName"] == app_name and a["AppType"] == "JupyterServer"]
    assert len(matching) == 1, f"expected exactly 1 matching app after the rejected duplicate, found {len(matching)}"

    # Positive control: the SAME AppType/AppName under a DIFFERENT user profile
    # in the same domain succeeds (the conflict is scoped to the exact tuple).
    sm.create_app(DomainId=domain_id, UserProfileName=profile2, AppType="JupyterServer", AppName=app_name)
    ctx.on_cleanup(
        lambda: _delete_and_wait(
            lambda: sm.delete_app(
                DomainId=domain_id, UserProfileName=profile2, AppType="JupyterServer", AppName=app_name
            ),
            lambda: sm.describe_app(
                DomainId=domain_id, UserProfileName=profile2, AppType="JupyterServer", AppName=app_name
            ),
        )
    )
    _poll_until(
        lambda: sm.describe_app(
            DomainId=domain_id, UserProfileName=profile2, AppType="JupyterServer", AppName=app_name
        )["Status"],
        lambda status: status in ("InService", "Failed"),
        timeout_s=900,
        interval_s=15,
        description=f"app {app_name} under {profile2} to leave Pending",
    )
    desc2 = sm.describe_app(
        DomainId=domain_id, UserProfileName=profile2, AppType="JupyterServer", AppName=app_name
    )
    assert desc2["AppName"] == app_name, (
        f"expected the same AppType/AppName under a different user profile to succeed, "
        f"describe_app returned {desc2.get('AppName')!r}"
    )


# ===== helpers =====


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-domain-role-")
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    )

    def _cleanup_role() -> None:
        _safe_call(
            lambda: iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
            )
        )
        _safe_call(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup_role)
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_err = exc
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("role propagation retry loop exited without a result")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} (last observed: {last!r})")


def _delete_and_wait(delete_fn, describe_fn, timeout_s: float = 240, interval_s: float = 2) -> None:
    from botocore.exceptions import ClientError

    try:
        delete_fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFound":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = describe_fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        # Some resources (e.g. Apps) keep a describable "Deleted" terminal record
        # instead of disappearing outright.
        if isinstance(resp, dict) and resp.get("Status") == "Deleted":
            return
        time.sleep(interval_s)
    raise AssertionError(f"teardown: resource still present {timeout_s}s after its delete: {resp!r}")


def _error(fn) -> tuple:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe_call(fn, timeout_s: float = 120.0) -> None:
    """Run a teardown delete: retry ResourceInUse while a dependency is released, return when the
    resource is already gone, raise everything else."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFound", "NoSuchEntity"):
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
