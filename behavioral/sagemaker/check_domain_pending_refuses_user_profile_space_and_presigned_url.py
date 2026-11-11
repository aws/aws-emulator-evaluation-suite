"""domain-pending-refuses-user-profile-space-and-presigned-url."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-pending-refuses-user-profile-space-and-presigned-url"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

MSG_PRESIGNED_PENDING = "Domain must be in either InService or Update_Failed state and not in: Pending"

#: Fresh domains tried for one still Pending after the three calls land, before failing.
_PENDING_WINDOW_ATTEMPTS = 3
_POLL_INTERVAL_S = 2.0
_DOMAIN_DELETE_TIMEOUT_S = 600.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While a new Studio Domain is Pending, CreateUserProfile and CreateSpace are refused with
    ValidationException naming the Domain as not InService, and CreatePresignedDomainUrl is refused
    naming the Pending state; once InService the same CreateUserProfile is accepted."""
    sm = ctx.client("sagemaker")
    net = ctx.network()
    vpc_id, subnet_id = net.vpc_id, net.subnet_ids[0]
    role_arn = _create_sagemaker_exec_role(ctx)

    domain_id, profile_name, space_name, refusals = _calls_while_pending(
        ctx, sm, role_arn, vpc_id, subnet_id
    )
    domain_arn = f"arn:aws:sagemaker:{ctx.region}:{ctx.account}:domain/{domain_id}"

    code, message = refusals["CreateUserProfile"]
    assert code == "ValidationException", f"CreateUserProfile on a Pending domain: expected ValidationException, got {code!r}"
    expected = (
        f"Unable to create UserProfile [arn:aws:sagemaker:{ctx.region}:{ctx.account}:user-profile/"
        f"{domain_id}/{profile_name}] because Domain [{domain_arn}] is not in InService."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    code, message = refusals["CreatePresignedDomainUrl"]
    assert code == "ValidationException", (
        f"CreatePresignedDomainUrl on a Pending domain: expected ValidationException, got {code!r}"
    )
    assert message == MSG_PRESIGNED_PENDING, f"expected {MSG_PRESIGNED_PENDING!r}, got {message!r}"

    code, message = refusals["CreateSpace"]
    assert code == "ValidationException", f"CreateSpace on a Pending domain: expected ValidationException, got {code!r}"
    expected = (
        f"Unable to create Space [arn:aws:sagemaker:{ctx.region}:{ctx.account}:space/"
        f"{domain_id}/{space_name}] because Domain [{domain_arn}] is not in InService."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Positive control: the refusals were the Pending state's, so the settled Domain accepts the
    # identical CreateUserProfile.
    status = _wait_domain_status(sm, domain_id, {"InService", "Failed"}, _budget_s(ctx, 600.0))
    assert status == "InService", f"domain {domain_id} settled {status!r}, expected InService"
    resp = sm.create_user_profile(
        DomainId=domain_id,
        UserProfileName=profile_name,
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    assert resp["UserProfileArn"].endswith(f"user-profile/{domain_id}/{profile_name}"), (
        f"unexpected UserProfileArn {resp['UserProfileArn']!r}"
    )

    # Teardown in the body, so the slow Domain deletion is not bound by the cleanup budget; the
    # registered cleanups tolerate what is already gone.
    _delete_domain_and_children(sm, domain_id, profile_name, space_name)


def _calls_while_pending(ctx, sm, role_arn, vpc_id, subnet_id):
    """Call the three operations on a fresh Domain until a read after them still shows it Pending;
    returns ``(domain_id, profile_name, space_name, refusals)``, refusals by operation."""
    seen = []
    for _ in range(_PENDING_WINDOW_ATTEMPTS):
        domain_id = _create_domain(ctx, sm, role_arn, vpc_id, subnet_id)
        profile_name = ctx.unique_name("sim2real-sm-up-")
        space_name = ctx.unique_name("sim2real-sm-sp-")
        ctx.on_cleanup(
            lambda d=domain_id, p=profile_name, s=space_name: _delete_domain_and_children(sm, d, p, s)
        )
        calls = {
            "CreateUserProfile": lambda: sm.create_user_profile(
                DomainId=domain_id, UserProfileName=profile_name
            ),
            "CreatePresignedDomainUrl": lambda: sm.create_presigned_domain_url(
                DomainId=domain_id, UserProfileName=profile_name
            ),
            "CreateSpace": lambda: sm.create_space(DomainId=domain_id, SpaceName=space_name),
        }
        refusals, accepted = {}, {}
        for op, call in calls.items():
            try:
                accepted[op] = call()
            except ClientError as exc:
                refusals[op] = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        status = sm.describe_domain(DomainId=domain_id)["Status"]
        if status == "Pending":
            assert not accepted, f"accepted while the Domain was still Pending: {sorted(accepted)}"
            return domain_id, profile_name, space_name, refusals
        seen.append(status)
        _delete_domain_and_children(sm, domain_id, profile_name, space_name)
    raise AssertionError(
        f"every new Domain had left Pending by the read after the three calls, so none landed "
        f"while it was Pending; statuses read: {seen}"
    )


def _create_domain(ctx, sm, role_arn, vpc_id, subnet_id) -> str:
    """CreateDomain, retried while the just-created execution role is not yet assumable."""
    domain_name = ctx.unique_name("sim2real-sm-domain-")
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        try:
            return sm.create_domain(
                DomainName=domain_name,
                AuthMode="IAM",
                DefaultUserSettings={"ExecutionRole": role_arn},
                DefaultSpaceSettings={"ExecutionRole": role_arn},
                SubnetIds=[subnet_id],
                VpcId=vpc_id,
                HomeEfsFileSystemCreation="Disabled",
                Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
            )["DomainId"]
        except ClientError as exc:
            err = exc.response["Error"]
            if (
                err["Code"] != "ValidationException"
                or "role" not in err.get("Message", "").lower()
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(_POLL_INTERVAL_S)


def _delete_domain_and_children(sm, domain_id, profile_name, space_name) -> None:
    """Delete the space and user profile a call may have created, then the Domain, and wait for
    each to be gone; a resource that is already gone is fine."""
    deadline = time.monotonic() + _DOMAIN_DELETE_TIMEOUT_S
    _delete_and_wait(
        lambda: sm.delete_space(DomainId=domain_id, SpaceName=space_name),
        lambda: sm.describe_space(DomainId=domain_id, SpaceName=space_name),
        deadline,
    )
    _delete_and_wait(
        lambda: sm.delete_user_profile(DomainId=domain_id, UserProfileName=profile_name),
        lambda: sm.describe_user_profile(DomainId=domain_id, UserProfileName=profile_name),
        deadline,
    )
    _delete_and_wait(
        lambda: sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"}),
        lambda: sm.describe_domain(DomainId=domain_id),
        deadline,
    )


def _delete_and_wait(delete, describe, deadline) -> None:
    """Call *delete*, retrying while the resource or a child is still settling (ResourceInUse, or
    a ValidationException asking to wait, as for a profile still pending creation), then poll
    *describe* until ResourceNotFound, all within *deadline*."""
    while True:
        try:
            delete()
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFound":
                return
            settling = code == "ResourceInUse" or (
                code == "ValidationException" and "Wait until" in exc.response["Error"].get("Message", "")
            )
            if not settling or time.monotonic() >= deadline:
                raise
        time.sleep(_POLL_INTERVAL_S)
    while True:
        try:
            last = describe()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"still present at the teardown deadline: {last.get('Status')!r}")
        time.sleep(_POLL_INTERVAL_S)


def _wait_domain_status(sm, domain_id, targets, timeout_s) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        status = sm.describe_domain(DomainId=domain_id)["Status"]
        if status in targets or time.monotonic() >= deadline:
            return status
        time.sleep(_POLL_INTERVAL_S)


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
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
