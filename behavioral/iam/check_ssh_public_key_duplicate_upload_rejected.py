"""ssh-public-key-duplicate-upload-rejected."""
from __future__ import annotations

import subprocess

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "ssh-public-key-duplicate-upload-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UploadSSHPublicKey rejects re-uploading a key the user already has with
    DuplicateSSHPublicKey, "Duplicate SSH public key uploaded.", keeping one key; once
    the original is deleted the same body uploads again."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-sshdup-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    public_key_pem = _generate_rsa_public_key_pem()

    uploaded = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=public_key_pem)[
        "SSHPublicKey"
    ]
    key_id = uploaded["SSHPublicKeyId"]
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id)
        )
    )

    code, message = _error(
        lambda: iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=public_key_pem)
    )
    assert code == "DuplicateSSHPublicKey", f"expected DuplicateSSHPublicKey, got {code!r}"
    assert message == "Duplicate SSH public key uploaded.", (
        f"DuplicateSSHPublicKey message: {message!r}"
    )

    # the rejected re-upload must not have created a second key entry
    keys = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]
    assert len(keys) == 1, f"expected exactly one key after the rejected duplicate upload, got {keys!r}"
    assert keys[0]["SSHPublicKeyId"] == key_id, (
        f"expected the surviving key to be the original {key_id!r}, got {keys[0]!r}"
    )

    # restore: once the only key is gone, the identical body is no longer a duplicate
    # and the same call that was just rejected must now succeed
    iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id)
    cleared = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]
    assert cleared == [], f"expected no keys after deleting the only key, got {cleared!r}"

    restored = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=public_key_pem)[
        "SSHPublicKey"
    ]
    new_key_id = restored["SSHPublicKeyId"]
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=new_key_id)
        )
    )
    final_keys = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]
    assert len(final_keys) == 1 and final_keys[0]["SSHPublicKeyId"] == new_key_id, (
        f"expected the identical body to upload cleanly once the duplicate was removed, got {final_keys!r}"
    )


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _generate_rsa_public_key_pem() -> str:
    require_tools("openssl")
    priv = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, text=True, timeout=30)
    if priv.returncode != 0:
        raise AssertionError(f"unreachable: openssl failed to generate a private key: {priv.stderr[:300]}")
    pub = subprocess.run(
        ["openssl", "rsa", "-pubout"], input=priv.stdout, capture_output=True, text=True, timeout=30
    )
    if pub.returncode != 0 or "BEGIN PUBLIC KEY" not in pub.stdout:
        raise AssertionError(f"unreachable: openssl failed to derive a public key: {pub.stderr[:300]}")
    return pub.stdout.strip() + "\n"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
