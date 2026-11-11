"""ssh-public-key-lifecycle."""
from __future__ import annotations

import subprocess

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "ssh-public-key-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SSH public key upload->active->status-updated->deleted->404 transitions and removal
    from list, that a mutation on the deleted key id also fails not-found (not just a read),
    and that the same key material is reusable once the key is genuinely gone."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-sshuser-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    public_key_pem = _generate_rsa_public_key_pem(ctx)

    uploaded = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=public_key_pem)["SSHPublicKey"]
    key_id = uploaded["SSHPublicKeyId"]
    assert uploaded["Status"] == "Active"
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id)
        )
    )

    got = iam.get_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id, Encoding="PEM")["SSHPublicKey"]
    assert got["Status"] == "Active"

    ids = {k["SSHPublicKeyId"] for k in iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]}
    assert key_id in ids

    iam.update_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id, Status="Inactive")
    got = iam.get_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id, Encoding="PEM")["SSHPublicKey"]
    assert got["Status"] == "Inactive"

    iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id)

    code, message = _error(
        lambda: iam.get_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id, Encoding="PEM")
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The Public Key with id {key_id} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    ids_after = {k["SSHPublicKeyId"] for k in iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]}
    assert key_id not in ids_after

    # a mutation on the dead id -- not just a read -- must also fail not-found
    code, message = _error(
        lambda: iam.update_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id, Status="Active")
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The Public Key with id {key_id} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the key material is reusable once genuinely gone: re-uploading the identical
    # body now succeeds as a brand-new key rather than DuplicateSSHPublicKey.
    reuploaded = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=public_key_pem)["SSHPublicKey"]
    reuploaded_id = reuploaded["SSHPublicKeyId"]
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=reuploaded_id)
        )
    )
    assert reuploaded["Status"] == "Active"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _generate_rsa_public_key_pem(ctx) -> str:
    """Generate a fresh 2048-bit RSA keypair and return only the SPKI public key PEM.

    IAM accepts SSH public keys encoded either in ssh-rsa or PEM format; PEM avoids
    needing an ssh-keygen binary that may not be present in the runtime image.
    """
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
