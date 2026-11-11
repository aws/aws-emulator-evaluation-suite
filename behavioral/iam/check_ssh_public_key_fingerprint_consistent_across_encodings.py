"""ssh-public-key-fingerprint-consistent-across-encodings."""
from __future__ import annotations

import subprocess

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "ssh-public-key-fingerprint-consistent-across-encodings"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSSHPublicKey returns the same Fingerprint for one uploaded key whether fetched as PEM or
    SSH, matching UploadSSHPublicKey's: the fingerprint belongs to the key, not the encoding.
    """
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-sshenc-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    ssh_pub = _generate_rsa_ssh_pubkey()
    uploaded = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=ssh_pub)["SSHPublicKey"]
    key_id = uploaded["SSHPublicKeyId"]
    ctx.on_cleanup(lambda: iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id))

    as_pem = iam.get_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id, Encoding="PEM")["SSHPublicKey"]
    as_ssh = iam.get_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id, Encoding="SSH")["SSHPublicKey"]

    assert as_pem["SSHPublicKeyBody"].startswith("-----BEGIN PUBLIC KEY-----"), (
        f"Encoding=PEM must actually return PEM, got {as_pem['SSHPublicKeyBody'][:40]!r}"
    )
    assert as_ssh["SSHPublicKeyBody"].startswith("ssh-rsa "), (
        f"Encoding=SSH must actually return the ssh-rsa form, got {as_ssh['SSHPublicKeyBody'][:40]!r}"
    )
    assert as_pem["Fingerprint"] == uploaded["Fingerprint"], (
        f"the PEM-encoded fetch's Fingerprint must match the one UploadSSHPublicKey minted for "
        f"this key: expected {uploaded['Fingerprint']!r}, got {as_pem['Fingerprint']!r}"
    )
    assert as_ssh["Fingerprint"] == uploaded["Fingerprint"], (
        f"the SSH-encoded fetch's Fingerprint must match the one UploadSSHPublicKey minted for "
        f"this key: expected {uploaded['Fingerprint']!r}, got {as_ssh['Fingerprint']!r}"
    )
    assert as_pem["Fingerprint"] == as_ssh["Fingerprint"], (
        f"the SAME key fetched in two different encodings must report the SAME Fingerprint: "
        f"PEM-encoded read got {as_pem['Fingerprint']!r}, SSH-encoded read got "
        f"{as_ssh['Fingerprint']!r}"
    )


def _generate_rsa_ssh_pubkey() -> str:
    require_tools("openssl", "ssh-keygen")
    priv = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, text=True, timeout=30)
    if priv.returncode != 0:
        raise AssertionError(f"unreachable: openssl genrsa failed: {priv.stderr[:300]}")
    pub = subprocess.run(
        ["ssh-keygen", "-y", "-f", "/dev/stdin"],
        input=priv.stdout, capture_output=True, text=True, timeout=30,
    )
    if pub.returncode != 0 or not pub.stdout.strip().startswith("ssh-rsa "):
        raise AssertionError(f"unreachable: ssh-keygen -y failed to derive an ssh-rsa public key: {pub.stderr[:300]}")
    return pub.stdout.strip()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
