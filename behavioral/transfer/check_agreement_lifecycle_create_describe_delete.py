"""agreement-lifecycle-create-describe-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agreement-lifecycle-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAgreement produces an ACTIVE agreement; DeleteAgreement removes it and DescribeAgreement 404s."""
    tf = ctx.client("transfer")
    server_id = _create_offline_server(ctx)
    role_arn = _create_transfer_role(ctx)
    local_profile_id = tf.create_profile(
        As2Id=ctx.unique_name("sim2real-local-as2-"), ProfileType="LOCAL"
    )["ProfileId"]
    ctx.on_cleanup(lambda: _safe_delete_profile(tf, local_profile_id))
    partner_profile_id = tf.create_profile(
        As2Id=ctx.unique_name("sim2real-partner-as2-"), ProfileType="PARTNER"
    )["ProfileId"]
    ctx.on_cleanup(lambda: _safe_delete_profile(tf, partner_profile_id))

    agreement_id = _retry_role_propagation(
        lambda: tf.create_agreement(
            ServerId=server_id,
            LocalProfileId=local_profile_id,
            PartnerProfileId=partner_profile_id,
            AccessRole=role_arn,
            BaseDirectory=f"/sim2real-agreement-{ctx.unique_name('sim2real-behav')}",
            Status="ACTIVE",
        )
    )["AgreementId"]
    ctx.on_cleanup(lambda: _safe_delete_agreement(tf, server_id, agreement_id))

    described = tf.describe_agreement(ServerId=server_id, AgreementId=agreement_id)["Agreement"]
    assert described["Status"] == "ACTIVE", f"expected ACTIVE, got {described['Status']}"
    assert described["LocalProfileId"] == local_profile_id, (
        f"expected LocalProfileId {local_profile_id}, got {described['LocalProfileId']}"
    )
    assert described["PartnerProfileId"] == partner_profile_id, (
        f"expected PartnerProfileId {partner_profile_id}, got {described['PartnerProfileId']}"
    )

    tf.delete_agreement(ServerId=server_id, AgreementId=agreement_id)
    error = _client_error(lambda: tf.describe_agreement(ServerId=server_id, AgreementId=agreement_id))
    assert error == ("ResourceNotFoundException", "Unknown agreement"), error


def _create_offline_server(ctx) -> str:
    tf = ctx.client("transfer")
    server_id = tf.create_server()["ServerId"]
    ctx.on_cleanup(lambda: _safe_delete_server(tf, server_id))
    return server_id


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-transfer-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "transfer.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    return role_arn


def _safe_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_server(tf, server_id: str) -> None:
    try:
        tf.delete_server(ServerId=server_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_profile(tf, profile_id: str) -> None:
    try:
        tf.delete_profile(ProfileId=profile_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_agreement(tf, server_id: str, agreement_id: str) -> None:
    try:
        tf.delete_agreement(ServerId=server_id, AgreementId=agreement_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _retry_role_propagation(fn, attempts: int = 6, delay_s: float = 3.0):
    """Retry a call that depends on a just-created IAM role, tolerating IAM's eventual consistency."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses cannot read as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
