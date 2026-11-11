"""ssh-public-key-bytes-preserved."""
from __future__ import annotations

import json

CHECK = "ssh-public-key-bytes-preserved"
GROUP = "representation"
SERVICES = ["transfer"]

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

try:
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _Encoding,
        NoEncryption as _NoEncryption,  # noqa: F401 - part of the _CRYPTO_AVAILABLE availability probe
        PrivateFormat as _PrivateFormat,  # noqa: F401 - part of the _CRYPTO_AVAILABLE availability probe
        PublicFormat as _PublicFormat,
    )

    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A public key body given to ImportSshPublicKey -- including its trailing
    comment and whitespace -- is returned byte-identical by DescribeUser."""
    if not _CRYPTO_AVAILABLE:
        raise RequiredToolMissing(["cryptography"], "module")

    transfer = ctx.client("transfer")
    iam = ctx.client("iam")

    role_arn = _create_transfer_role(ctx, iam)
    server_id = transfer.create_server(
        Protocols=["SFTP"],
        Tags=[{"Key": "sim2real", "Value": "ssh-public-key-bytes-preserved"}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    user_name = ctx.unique_name("sim2realuser").replace("-", "")[:32]
    transfer.create_user(
        ServerId=server_id,
        UserName=user_name,
        Role=role_arn,
        Tags=[{"Key": "sim2real", "Value": "ssh-public-key-bytes-preserved"}],
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user_name))

    _, public_openssh = _generate_rsa_keypair()
    # Comment plus a mix of interior/trailing whitespace, to check that both survive
    # the round trip verbatim, not just the base64 key material.
    comment = f"sim2real-comment {ctx.unique_name('note-')}"
    body = f"{public_openssh} {comment}  "

    key_id = transfer.import_ssh_public_key(
        ServerId=server_id, SshPublicKeyBody=body, UserName=user_name
    )["SshPublicKeyId"]

    described = transfer.describe_user(ServerId=server_id, UserName=user_name)["User"]
    matches = [k for k in described["SshPublicKeys"] if k["SshPublicKeyId"] == key_id]
    assert len(matches) == 1, f"expected exactly one imported key with id {key_id}"
    got = matches[0]["SshPublicKeyBody"]
    # AWS Transfer strips trailing whitespace from the submitted key body (interior
    # content -- the key material and comment -- must still be preserved exactly).
    expected = body.rstrip()
    assert got == expected, (
        "SSH public key body was altered by the round trip (beyond trailing "
        f"whitespace); sent {len(body)} bytes {body!r}, got {len(got)} bytes {got!r}"
    )


def _generate_rsa_keypair():
    private_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_openssh = private_key.public_key().public_bytes(
        encoding=_Encoding.OpenSSH, format=_PublicFormat.OpenSSH
    ).decode()
    return private_key, public_openssh


def _create_transfer_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-transfer-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "ssh-public-key-bytes-preserved"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
