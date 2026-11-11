"""ssh-public-key-body-encoding-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ssh-public-key-body-encoding-round-trip"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PublicKeyMaterial uploaded in either PEM or SSH encoding is returned
    byte-identical by GetSSHPublicKey when the same encoding is requested."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-sshrt-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    # Use two DIFFERENT RSA keypairs so the two uploads are not the same key
    # material (IAM rejects re-uploading the identical key as DuplicateSSHPublicKey).
    ssh_pub, _unused_pem1 = _generate_rsa_ssh_and_pem_pubkeys()
    _unused_ssh2, pem_pub = _generate_rsa_ssh_and_pem_pubkeys()

    # SSH-encoded upload, SSH-encoded retrieval
    uploaded_ssh = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=ssh_pub)[
        "SSHPublicKey"
    ]
    ssh_key_id = uploaded_ssh["SSHPublicKeyId"]
    ctx.on_cleanup(
        lambda: iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=ssh_key_id)
    )
    fetched_ssh = iam.get_ssh_public_key(
        UserName=user_name, SSHPublicKeyId=ssh_key_id, Encoding="SSH"
    )["SSHPublicKey"]["SSHPublicKeyBody"]
    assert fetched_ssh.strip() == ssh_pub.strip(), (
        f"SSH-uploaded key must round-trip byte-identical in SSH encoding: "
        f"expected {ssh_pub.strip()!r}, got {fetched_ssh.strip()!r}"
    )

    # PEM-encoded upload, PEM-encoded retrieval (different key material from above)
    uploaded_pem = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=pem_pub)[
        "SSHPublicKey"
    ]
    pem_key_id = uploaded_pem["SSHPublicKeyId"]
    ctx.on_cleanup(
        lambda: iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=pem_key_id)
    )
    fetched_pem = iam.get_ssh_public_key(
        UserName=user_name, SSHPublicKeyId=pem_key_id, Encoding="PEM"
    )["SSHPublicKey"]["SSHPublicKeyBody"]
    assert fetched_pem.strip() == pem_pub.strip(), (
        f"PEM-uploaded key must round-trip byte-identical in PEM encoding: "
        f"expected {pem_pub.strip()!r}, got {fetched_pem.strip()!r}"
    )


def _generate_rsa_ssh_and_pem_pubkeys():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key()
    ssh_pub = pub.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("ascii")
    pem_pub = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return ssh_pub, pem_pub


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
