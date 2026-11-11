"""import-ssh-public-key-duplicate-rejected."""
from __future__ import annotations

import base64
import json
import secrets
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-ssh-public-key-duplicate-rejected"
GROUP = "negative-classes"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-importing the exact same SSH public key for a user is rejected with
    ResourceExistsException rather than silently registering a second copy."""
    transfer = ctx.client("transfer")
    role_arn = _create_transfer_role(ctx)
    server_id = _create_basic_server(ctx)
    user_name = ctx.unique_name("sim2real-behav-sshuser-")
    transfer.create_user(
        ServerId=server_id,
        UserName=user_name,
        Role=role_arn,
        HomeDirectory="/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user_name))

    key_a = _fake_ssh_rsa_public_key("sim2real-key-a")
    imported = transfer.import_ssh_public_key(
        ServerId=server_id, UserName=user_name, SshPublicKeyBody=key_a
    )
    key_a_id = imported["SshPublicKeyId"]
    ctx.on_cleanup(lambda: _delete_key_if_present(transfer, server_id, user_name, key_a_id))

    def _key_count() -> int:
        described = transfer.describe_user(ServerId=server_id, UserName=user_name)
        return len(described["User"]["SshPublicKeys"])

    assert _key_count() == 1, "positive control: the initial key import must be registered"

    code, message = _err(
        lambda: transfer.import_ssh_public_key(
            ServerId=server_id, UserName=user_name, SshPublicKeyBody=key_a
        )
    )
    assert code == "ResourceExistsException", f"expected ResourceExistsException, got {code!r}"
    assert message == "Public key already exists", f"unexpected duplicate key message {message!r}"

    # effect absent: the duplicate import did not add a second copy of the same key
    assert _key_count() == 1, "the duplicate SSH key import was persisted"

    # restore: the duplicate rejection is scoped to this key existing on this user, not a
    # permanent block on the body -- deleting the original key and reimporting the byte-identical
    # body must now succeed.
    transfer.delete_ssh_public_key(ServerId=server_id, UserName=user_name, SshPublicKeyId=key_a_id)
    assert _key_count() == 0, "deleting the only imported key must leave the user with none"

    restored = transfer.import_ssh_public_key(
        ServerId=server_id, UserName=user_name, SshPublicKeyBody=key_a
    )
    restored_key_id = restored["SshPublicKeyId"]
    ctx.on_cleanup(
        lambda: transfer.delete_ssh_public_key(
            ServerId=server_id, UserName=user_name, SshPublicKeyId=restored_key_id
        )
    )
    assert _key_count() == 1, (
        "reimporting the identical key body must succeed once the duplicate is deleted"
    )

    # positive control: importing a genuinely different key for the same user succeeds
    key_b = _fake_ssh_rsa_public_key("sim2real-key-b")
    imported_b = transfer.import_ssh_public_key(
        ServerId=server_id, UserName=user_name, SshPublicKeyBody=key_b
    )
    key_b_id = imported_b["SshPublicKeyId"]
    ctx.on_cleanup(
        lambda: transfer.delete_ssh_public_key(
            ServerId=server_id, UserName=user_name, SshPublicKeyId=key_b_id
        )
    )
    assert _key_count() == 2, "a genuinely distinct key must import alongside the restored one"
    assert key_b_id != restored_key_id, "a distinct key body must get a distinct SshPublicKeyId"


def _err(fn: Callable[[], Any]) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_key_if_present(transfer, server_id: str, user_name: str, key_id: str) -> None:
    try:
        transfer.delete_ssh_public_key(
            ServerId=server_id, UserName=user_name, SshPublicKeyId=key_id
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sshrole-")
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_basic_server(ctx) -> str:
    transfer = ctx.client("transfer")
    resp = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="SERVICE_MANAGED",
        EndpointType="PUBLIC",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    server_id = resp["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))
    return server_id


def _mpint(n: int) -> bytes:
    if n == 0:
        return (0).to_bytes(4, "big")
    data = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if data[0] & 0x80:
        data = b"\x00" + data
    return len(data).to_bytes(4, "big") + data


def _ssh_string(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def _fake_ssh_rsa_public_key(comment: str) -> str:
    """Build a structurally-valid (but non-functional) 2048-bit ssh-rsa public key blob.

    AWS Transfer Family validates that an SshPublicKeyBody parses as a well-formed SSH
    public key; it does not require the key to be cryptographically sound, so a random
    modulus with the standard RSA public exponent is sufficient and avoids depending on
    an external crypto library just to generate throwaway test key material.
    """
    exponent = 65537
    modulus = secrets.randbits(2048) | (1 << 2047) | 1
    blob = _ssh_string(b"ssh-rsa") + _mpint(exponent) + _mpint(modulus)
    encoded = base64.b64encode(blob).decode("ascii")
    return f"ssh-rsa {encoded} {comment}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
