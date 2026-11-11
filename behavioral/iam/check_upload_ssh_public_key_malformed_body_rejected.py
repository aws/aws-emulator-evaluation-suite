"""upload-ssh-public-key-malformed-body-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "upload-ssh-public-key-malformed-body-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]

_MSG_UNRECOGNIZED = "Invalid public key uploaded."
_MSG_DUPLICATE = "Duplicate SSH public key uploaded."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UploadSSHPublicKey rejects an unstructured key body with
    UnrecognizedPublicKeyEncoding and its exact message, storing nothing; a valid key
    uploads Active, and re-uploading it fails with DuplicateSSHPublicKey."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-sshuser-")
    iam.create_user(
        UserName=user_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    # Case 1: totally unstructured body -- no recognizable SSH/PEM framing at all.
    garbage_body = "this-is-not-a-valid-ssh-or-pem-public-key " * 5
    err = _client_error(
        lambda: iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=garbage_body)
    )
    code = err.get("Code")
    assert code == "UnrecognizedPublicKeyEncoding", repr(err)
    assert err.get("Message") == _MSG_UNRECOGNIZED, (err.get("Message"), _MSG_UNRECOGNIZED)

    # effect absent: no key record was created for the malformed body
    keys = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]
    assert keys == [], f"malformed upload must not create a key record, got {keys!r}"

    # positive control: a structurally valid, not-yet-seen ssh-rsa key uploads cleanly
    ssh_pub, _pem_pub = _generate_rsa_ssh_and_pem_pubkeys()
    uploaded = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=ssh_pub)[
        "SSHPublicKey"
    ]
    key_id = uploaded["SSHPublicKeyId"]
    ctx.on_cleanup(lambda: iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id))
    assert uploaded["Status"] == "Active", f"expected a freshly uploaded key to be Active, got {uploaded['Status']!r}"
    keys_after = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]
    assert len(keys_after) == 1 and keys_after[0]["SSHPublicKeyId"] == key_id, (
        f"expected exactly the uploaded key {key_id!r} to be listed, got {keys_after!r}"
    )

    # Case 2: re-uploading the SAME already-associated key is a distinct rejection
    # path (DuplicateSSHPublicKey), not the UnrecognizedPublicKeyEncoding of case 1.
    dup = _client_error(
        lambda: iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=ssh_pub)
    )
    dup_code = dup.get("Code")
    assert dup_code == "DuplicateSSHPublicKey", repr(dup)
    assert dup.get("Message") == _MSG_DUPLICATE, (dup.get("Message"), _MSG_DUPLICATE)
    assert dup_code != code, "duplicate-key rejection must be distinct from the malformed-body rejection"

    # effect absent: the duplicate attempt did not create a second key record
    keys_final = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]
    assert len(keys_final) == 1 and keys_final[0]["SSHPublicKeyId"] == key_id, (
        f"a rejected duplicate upload must leave exactly the original key {key_id!r} listed, "
        f"got {keys_final!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
