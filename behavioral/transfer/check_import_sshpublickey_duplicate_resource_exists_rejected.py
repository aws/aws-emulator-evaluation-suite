"""import-sshpublickey-duplicate-resource-exists-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "import-sshpublickey-duplicate-resource-exists-rejected"
GROUP = "error-semantics"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportSshPublicKey twice with the same public key for a user returns
    ResourceExistsException on the second call, the user's key list is not double-counted,
    and importing a genuinely distinct key for that user still succeeds (positive control)."""
    try:
        pubkey1 = _generate_rsa_openssh_public_key()
        pubkey2 = _generate_rsa_openssh_public_key()
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

    key_id1 = transfer.import_ssh_public_key(
        ServerId=server_id, UserName=username, SshPublicKeyBody=pubkey1
    )["SshPublicKeyId"]

    code, message = _err(
        lambda: transfer.import_ssh_public_key(
            ServerId=server_id, UserName=username, SshPublicKeyBody=pubkey1
        )
    )
    assert code == "ResourceExistsException", f"expected ResourceExistsException, got {code}"
    assert message == "Public key already exists", f"unexpected duplicate key message {message!r}"

    # Effect absent: the duplicate attempt did not add a second entry for that key.
    desc = transfer.describe_user(ServerId=server_id, UserName=username)["User"]
    matching = [k for k in desc["SshPublicKeys"] if k["SshPublicKeyId"] == key_id1]
    assert len(matching) == 1, f"expected exactly one entry for the imported key, got {len(matching)}"

    # Positive control: a genuinely distinct key imports successfully for the same user.
    key_id2 = transfer.import_ssh_public_key(
        ServerId=server_id, UserName=username, SshPublicKeyBody=pubkey2
    )["SshPublicKeyId"]
    assert key_id2 != key_id1, f"expected a new key id, got the same id {key_id1!r} back"

    # Terminal read: independent of the mutating call, confirms the second key actually
    # persisted rather than just returning a fresh-looking id.
    desc_after = transfer.describe_user(ServerId=server_id, UserName=username)["User"]
    key_ids_after = [k["SshPublicKeyId"] for k in desc_after["SshPublicKeys"]]
    assert key_id2 in key_ids_after, f"expected {key_id2} in the user's key list, got {key_ids_after}"
    assert len(key_ids_after) == 2, f"expected exactly 2 keys after the positive control, got {len(key_ids_after)}"


def _err(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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
