"""sshpublickey-import-attach-delete-reflected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "sshpublickey-import-attach-delete-reflected"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportSshPublicKey attaches a key to a user's SshPublicKeys; DeleteSshPublicKey removes it."""
    try:
        pubkey_body = _generate_rsa_openssh_public_key()
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"], "module") from exc

    transfer = ctx.client("transfer")
    role_arn = _create_transfer_role(ctx)
    server_id = _create_server(ctx, transfer)
    username = ctx.unique_name("sim2real-user-")

    _retry_role_propagation(
        lambda: transfer.create_user(
            ServerId=server_id,
            UserName=username,
            Role=role_arn,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )

    def _cleanup_user():
        try:
            transfer.delete_user(ServerId=server_id, UserName=username)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_user)

    key_id = transfer.import_ssh_public_key(
        ServerId=server_id, UserName=username, SshPublicKeyBody=pubkey_body
    )["SshPublicKeyId"]

    desc = transfer.describe_user(ServerId=server_id, UserName=username)["User"]
    ids_after_import = {k["SshPublicKeyId"] for k in desc["SshPublicKeys"]}
    assert key_id in ids_after_import, "imported key not reflected in DescribeUser.SshPublicKeys"

    transfer.delete_ssh_public_key(ServerId=server_id, SshPublicKeyId=key_id, UserName=username)

    desc2 = transfer.describe_user(ServerId=server_id, UserName=username)["User"]
    ids_after_delete = {k["SshPublicKeyId"] for k in desc2.get("SshPublicKeys", [])}
    assert key_id not in ids_after_delete, "deleted key still present in DescribeUser.SshPublicKeys"

    try:
        transfer.delete_ssh_public_key(ServerId=server_id, SshPublicKeyId=key_id, UserName=username)
        raise AssertionError(
            f"re-deleting the already-deleted SshPublicKeyId {key_id!r} unexpectedly succeeded"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"deleting a gone SshPublicKeyId should raise ResourceNotFoundException, got {code!r}"
        )
        message = exc.response["Error"].get("Message")
        assert message == "Unknown public key ID", (
            f"unexpected message re-deleting a gone SshPublicKeyId: {message!r}"
        )


def _create_server(ctx, transfer, **kwargs):
    server_id = transfer.create_server(
        Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )["ServerId"]

    def _cleanup():
        try:
            transfer.delete_server(ServerId=server_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return server_id


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _generate_rsa_openssh_public_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    return pub_bytes.decode("ascii")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
