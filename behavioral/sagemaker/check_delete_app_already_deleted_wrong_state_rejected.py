"""delete-app-already-deleted-wrong-state-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "delete-app-already-deleted-wrong-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second DeleteApp while the app is still Deleting is refused with ValidationException and its exact message,
    and the app keeps its ARN and stays Deleting or Deleted; the first DeleteApp is accepted and starts the transition.
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
        )
    )
    domain_id = created["DomainArn"].rsplit("/", 1)[-1]
    ctx.on_cleanup(
        lambda: _delete_and_wait(
            lambda: sm.delete_domain(
                DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"}
            ),
            lambda: sm.describe_domain(DomainId=domain_id)["Status"],
            timeout_s=900,
        )
    )
    domain_status = _poll_until(
        lambda: sm.describe_domain(DomainId=domain_id)["Status"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=900,
        interval_s=20,
    )
    assert domain_status == "InService", f"domain never reached InService: {domain_status}"

    profile_name = ctx.unique_name("sim2real-profile-")
    sm.create_user_profile(DomainId=domain_id, UserProfileName=profile_name)
    ctx.on_cleanup(
        lambda: _delete_and_wait(
            lambda: sm.delete_user_profile(DomainId=domain_id, UserProfileName=profile_name),
            lambda: sm.describe_user_profile(DomainId=domain_id, UserProfileName=profile_name)[
                "Status"
            ],
            timeout_s=600,
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

    app_name = ctx.unique_name("sim2real-app-")
    sm.create_app(
        DomainId=domain_id,
        UserProfileName=profile_name,
        AppType="JupyterServer",
        AppName=app_name,
    )
    ctx.on_cleanup(
        lambda: _delete_and_wait(
            lambda: sm.delete_app(
                DomainId=domain_id,
                UserProfileName=profile_name,
                AppType="JupyterServer",
                AppName=app_name,
            ),
            lambda: sm.describe_app(
                DomainId=domain_id,
                UserProfileName=profile_name,
                AppType="JupyterServer",
                AppName=app_name,
            )["Status"],
            timeout_s=600,
        )
    )
    app_status = _poll_until(
        lambda: sm.describe_app(
            DomainId=domain_id, UserProfileName=profile_name, AppType="JupyterServer", AppName=app_name
        )["Status"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=300,
        interval_s=10,
    )
    assert app_status == "InService", f"app never reached InService: {app_status}"

    # (c) positive control: the first DeleteApp call succeeds and starts the
    # Deleting transition.
    sm.delete_app(
        DomainId=domain_id, UserProfileName=profile_name, AppType="JupyterServer", AppName=app_name
    )
    describe_kwargs = dict(
        DomainId=domain_id, UserProfileName=profile_name, AppType="JupyterServer", AppName=app_name
    )
    after_first_delete = sm.describe_app(**describe_kwargs)
    assert after_first_delete["Status"] in ("Deleting", "Deleted"), (
        f"expected Deleting or Deleted after the first DeleteApp, got {after_first_delete['Status']!r}"
    )

    # Negative: a second DeleteApp while it is still transitioning is rejected with
    # ValidationException, not ResourceInUse, and the message
    # names the App as already being deleted rather than describing a malformed request.
    code, message = _error_code(lambda: sm.delete_app(**describe_kwargs))
    assert code == "ValidationException", f"expected ValidationException, got {code} ({message!r})"
    expected = f"App [{app_name}] is already being deleted. Wait until the app is deleted."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # (b) effect absent: the rejected duplicate delete did not corrupt the App's
    # lifecycle -- it is still the same App, still on its normal deletion path.
    after_second_delete = sm.describe_app(**describe_kwargs)
    assert after_second_delete["AppArn"] == after_first_delete["AppArn"], (
        f"rejected duplicate delete changed the App identity: "
        f"{after_first_delete['AppArn']!r} -> {after_second_delete['AppArn']!r}"
    )
    assert after_second_delete["Status"] in ("Deleting", "Deleted"), (
        f"expected Deleting or Deleted after the rejected duplicate delete, "
        f"got {after_second_delete['Status']!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _delete_and_wait(delete, status, *, timeout_s, interval_s=15.0):
    """Teardown: delete (tolerating a delete already in flight or a resource already
    gone), then wait until the resource is Deleted or not found, so a parent
    delete that needs its children gone does not fail and leak."""
    from botocore.exceptions import ClientError

    try:
        delete()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFound", "ValidationException"):
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            current = status()
        except ClientError as err:
            if err.response["Error"]["Code"] in ("ResourceNotFound", "ValidationException"):
                return
            raise
        if current == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown: resource still {current!r} after {timeout_s}s")
        time.sleep(interval_s)


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


def _retry_role_propagation(fn, timeout_s=60.0, interval_s=5.0):
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
