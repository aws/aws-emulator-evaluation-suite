"""delete-server-referenced-by-agreement-succeeds-and-orphans-agreement."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-server-referenced-by-agreement-succeeds-and-orphans-agreement"
GROUP = "negative-classes"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteServer succeeds despite an ACTIVE agreement referencing it; afterwards the server and
    the orphaned agreement both answer ResourceNotFoundException to describe and delete."""
    transfer = ctx.client("transfer")
    role_arn = _create_transfer_role(ctx)
    server_id = _create_basic_server(ctx)
    local_profile_id = _create_profile(ctx, "LOCAL")
    partner_profile_id = _create_profile(ctx, "PARTNER")
    bucket_name = _create_bucket(ctx)

    agreement = transfer.create_agreement(
        ServerId=server_id,
        LocalProfileId=local_profile_id,
        PartnerProfileId=partner_profile_id,
        AccessRole=role_arn,
        BaseDirectory=f"/{bucket_name}",
    )
    agreement_id = agreement["AgreementId"]

    described = transfer.describe_agreement(ServerId=server_id, AgreementId=agreement_id)
    assert described["Agreement"]["Status"] == "ACTIVE", (
        f"expected a freshly created agreement to be ACTIVE, got {described['Agreement']['Status']!r}"
    )

    # DeleteServer succeeds even though an ACTIVE agreement still references it.
    transfer.delete_server(ServerId=server_id)

    # effect: the server is gone ...
    server_gone_code, server_gone_message = _error(lambda: transfer.describe_server(ServerId=server_id))
    assert server_gone_code == "ResourceNotFoundException", (
        f"expected the deleted server to be gone, got {server_gone_code!r}"
    )
    assert server_gone_message == "Unknown server", f"unexpected not-found message: {server_gone_message!r}"

    # ... and the now-orphaned agreement is no longer reachable through the normal
    # ServerId+AgreementId lookup either -- it doesn't linger in a half-deleted state.
    agreement_gone_code, agreement_gone_message = _error(
        lambda: transfer.describe_agreement(ServerId=server_id, AgreementId=agreement_id)
    )
    assert agreement_gone_code == "ResourceNotFoundException", (
        f"expected the orphaned agreement to be unreachable, got {agreement_gone_code!r}"
    )
    assert agreement_gone_message == "Unknown agreement", f"unexpected not-found message: {agreement_gone_message!r}"

    # ... and a mutation on the orphaned agreement fails too -- it is genuinely gone,
    # not merely hidden from the read path.
    agreement_delete_code, agreement_delete_message = _error(
        lambda: transfer.delete_agreement(ServerId=server_id, AgreementId=agreement_id)
    )
    assert agreement_delete_code == "ResourceNotFoundException", (
        f"expected DeleteAgreement on the orphaned agreement to fail, got {agreement_delete_code!r}"
    )
    assert agreement_delete_message == "Unknown agreement", f"unexpected not-found message: {agreement_delete_message!r}"

    # a mutation on the deleted server fails too -- it is genuinely gone, not just
    # hidden from the read path.
    server_delete_again_code, server_delete_again_message = _error(lambda: transfer.delete_server(ServerId=server_id))
    assert server_delete_again_code == "ResourceNotFoundException", (
        f"expected a second DeleteServer on the deleted server to fail, got {server_delete_again_code!r}"
    )
    assert server_delete_again_message == "Unknown server", f"unexpected not-found message: {server_delete_again_message!r}"

    # positive control: a server with no agreements also deletes cleanly
    empty_server_id = _create_basic_server(ctx)
    transfer.delete_server(ServerId=empty_server_id)
    not_found_code, not_found_message = _error(lambda: transfer.describe_server(ServerId=empty_server_id))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected the emptied-and-deleted server to be gone, got {not_found_code!r}"
    )
    assert not_found_message == "Unknown server", f"unexpected not-found message: {not_found_message!r}"



def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-agrrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "transfer.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_basic_server(ctx) -> str:
    transfer = ctx.client("transfer")
    server_name = ctx.unique_name("sim2real-behav-agrsrv-")
    resp = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="SERVICE_MANAGED",
        EndpointType="PUBLIC",
        Tags=[{"Key": "Name", "Value": server_name}],
    )
    server_id = resp["ServerId"]

    def _cleanup() -> None:
        try:
            transfer.delete_server(ServerId=server_id)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return server_id


def _create_profile(ctx, profile_type: str) -> str:
    transfer = ctx.client("transfer")
    as2_id = ctx.unique_name("sim2real-as2-").upper().replace("-", "")[:32]
    resp = transfer.create_profile(
        As2Id=as2_id,
        ProfileType=profile_type,
        Tags=[{"Key": "Name", "Value": as2_id}],
    )
    profile_id = resp["ProfileId"]
    ctx.on_cleanup(lambda: _delete_profile_once_unreferenced(transfer, profile_id))
    return profile_id


def _delete_profile_once_unreferenced(transfer, profile_id: str, timeout_s: float = 600.0) -> None:
    """An orphaned agreement keeps its profiles "in use" until AWS reaps it; retry DeleteProfile
    on that refusal until the deadline, then let the last error raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            transfer.delete_profile(ProfileId=profile_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "InvalidRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(15)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-agrbkt-").lower()
    region = s3.meta.region_name
    if region and region != "us-east-1":
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
    else:
        s3.create_bucket(Bucket=bucket_name)
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "Name", "Value": bucket_name}]}
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    return bucket_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
