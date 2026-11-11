"""ssh-public-key-duplicate-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ssh-public-key-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Uploading the same SSH public key body twice for a user fails with
    DuplicateSSHPublicKey and its exact message and leaves exactly one key; after that
    key is deleted, the identical body uploads again."""
    iam = ctx.client("iam")
    key_body = _generate_ssh_public_key()

    user_name = ctx.unique_name("sim2real-sshdup-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    first = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=key_body)["SSHPublicKey"]
    key_id = first["SSHPublicKeyId"]
    ctx.on_cleanup(lambda: _best_effort_delete_ssh_key(iam, user_name, key_id))

    code, message = _error(lambda: iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=key_body))
    assert code == "DuplicateSSHPublicKey", f"expected DuplicateSSHPublicKey, got {code}"
    expected = "Duplicate SSH public key uploaded."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]
    assert len(listed) == 1 and listed[0]["SSHPublicKeyId"] == key_id, (
        f"expected exactly one key after rejected duplicate upload, got {listed}"
    )

    iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id)
    after_delete = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]
    assert after_delete == [], f"expected no keys left after deleting the original, got {after_delete}"

    restored = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=key_body)["SSHPublicKey"]
    restored_id = restored["SSHPublicKeyId"]
    ctx.on_cleanup(lambda: _best_effort_delete_ssh_key(iam, user_name, restored_id))

    listed_after_restore = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]
    assert len(listed_after_restore) == 1 and listed_after_restore[0]["SSHPublicKeyId"] == restored_id, (
        "expected the identical body to upload successfully once the original key was "
        f"removed, got {listed_after_restore}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _generate_ssh_public_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ssh_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    return ssh_bytes.decode() + " sim2real-behavioral"


def _best_effort_delete_ssh_key(iam, user_name, key_id) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
