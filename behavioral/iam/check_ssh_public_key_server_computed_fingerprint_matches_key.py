"""ssh-public-key-server-computed-fingerprint-matches-key."""
from __future__ import annotations

import base64
import hashlib

from behavioral_harness import tags

CHECK = "ssh-public-key-server-computed-fingerprint-matches-key"
GROUP = "server-side"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The Fingerprint returned by GetSSHPublicKey (and by UploadSSHPublicKey) is the
    correct MD5 digest computed server-side from the exact bytes of the uploaded public
    key -- not a client-echoed or placeholder value."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    iam = ctx.client("iam")
    username = ctx.unique_name("sim2real-sshkey-")
    iam.create_user(UserName=username, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=username))

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    pubkey_body = public_bytes.decode("ascii")
    expected_fingerprint = _ssh_md5_fingerprint(pubkey_body)

    upload_resp = iam.upload_ssh_public_key(UserName=username, SSHPublicKeyBody=pubkey_body)
    key_id = upload_resp["SSHPublicKey"]["SSHPublicKeyId"]
    ctx.on_cleanup(lambda: iam.delete_ssh_public_key(UserName=username, SSHPublicKeyId=key_id))

    assert upload_resp["SSHPublicKey"]["Fingerprint"] == expected_fingerprint, (
        f"UploadSSHPublicKey fingerprint {upload_resp['SSHPublicKey']['Fingerprint']!r} != "
        f"expected {expected_fingerprint!r}"
    )

    get_resp = iam.get_ssh_public_key(UserName=username, SSHPublicKeyId=key_id, Encoding="SSH")
    assert get_resp["SSHPublicKey"]["Fingerprint"] == expected_fingerprint, (
        f"GetSSHPublicKey fingerprint {get_resp['SSHPublicKey']['Fingerprint']!r} != "
        f"expected {expected_fingerprint!r}"
    )


def _ssh_md5_fingerprint(pubkey_body: str) -> str:
    parts = pubkey_body.strip().split()
    blob = base64.b64decode(parts[1])
    digest = hashlib.md5(blob).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
