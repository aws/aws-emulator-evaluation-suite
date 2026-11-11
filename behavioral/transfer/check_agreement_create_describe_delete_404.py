"""agreement-create-describe-delete-404."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agreement-create-describe-delete-404"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAgreement is describable; DeleteAgreement causes DescribeAgreement to 404."""
    transfer = ctx.client("transfer")

    role_arn = _create_transfer_role(ctx)
    server_id = _create_server(ctx, transfer)
    local_profile_id = _create_profile(ctx, transfer, "LOCAL")
    partner_profile_id = _create_profile(ctx, transfer, "PARTNER")

    agreement_id = _retry_role_propagation(
        lambda: transfer.create_agreement(
            ServerId=server_id,
            LocalProfileId=local_profile_id,
            PartnerProfileId=partner_profile_id,
            AccessRole=role_arn,
            Status="ACTIVE",
            BaseDirectory=f"/{ctx.unique_name('sim2real-agreement-bucket')}/home",
            Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-agreement-")}],
        )
    )["AgreementId"]

    def _cleanup_agreement():
        try:
            transfer.delete_agreement(ServerId=server_id, AgreementId=agreement_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_agreement)

    desc = transfer.describe_agreement(ServerId=server_id, AgreementId=agreement_id)["Agreement"]
    assert desc["Status"] == "ACTIVE", f"expected ACTIVE, got {desc['Status']}"
    assert desc["LocalProfileId"] == local_profile_id, (
        f"expected local profile {local_profile_id}, got {desc['LocalProfileId']}"
    )
    assert desc["PartnerProfileId"] == partner_profile_id, (
        f"expected partner profile {partner_profile_id}, got {desc['PartnerProfileId']}"
    )

    transfer.delete_agreement(ServerId=server_id, AgreementId=agreement_id)
    error = _client_error(lambda: transfer.describe_agreement(ServerId=server_id, AgreementId=agreement_id))
    assert error == ("ResourceNotFoundException", "Unknown agreement"), error


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses cannot read as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_server(ctx, transfer, **kwargs):
    kwargs.setdefault("Tags", [{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-srv-")}])
    server_id = transfer.create_server(**kwargs)["ServerId"]

    def _cleanup():
        try:
            transfer.delete_server(ServerId=server_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return server_id


def _create_profile(ctx, transfer, profile_type: str) -> str:
    as2_id = ctx.unique_name(f"sim2real-{profile_type.lower()}-")
    profile_id = transfer.create_profile(
        As2Id=as2_id,
        ProfileType=profile_type,
        Tags=[{"Key": "Name", "Value": as2_id}],
    )["ProfileId"]

    def _cleanup():
        try:
            transfer.delete_profile(ProfileId=profile_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return profile_id


def _create_transfer_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-transfer-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_role_propagation(fn, attempts: int = 8, delay_s: float = 3.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidRequestException", "AccessDenied", "AccessDeniedException"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
