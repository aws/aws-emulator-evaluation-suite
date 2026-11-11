"""get-ssh-public-key-unrecognized-encoding-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-ssh-public-key-unrecognized-encoding-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSSHPublicKey rejects an Encoding value outside {SSH, PEM} with
    ValidationError (server-side enum-constraint validation), while a recognized
    encoding still retrieves the key."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-sshuser-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    ssh_pub, _pem_pub = _generate_rsa_ssh_and_pem_pubkeys()
    uploaded = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=ssh_pub)[
        "SSHPublicKey"
    ]
    key_id = uploaded["SSHPublicKeyId"]
    ctx.on_cleanup(lambda: iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id))

    code, message = _error(
        lambda: iam.get_ssh_public_key(
            UserName=user_name, SSHPublicKeyId=key_id, Encoding="BASE64"
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}: {message!r}"
    expected = (
        "1 validation error detected: Value at 'encoding' failed to satisfy constraint: "
        "Member must satisfy enum value set: [SSH, PEM]"
    )
    assert message == expected, f"ValidationError message: expected {expected!r}, got {message!r}"

    # positive control: a recognized encoding still resolves the same key afterwards
    resp = iam.get_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id, Encoding="SSH")[
        "SSHPublicKey"
    ]
    assert resp["SSHPublicKeyId"] == key_id, (
        f"a recognized Encoding must still resolve the same key, got {resp.get('SSHPublicKeyId')!r}"
    )
    assert resp["Status"] == "Active", (
        f"the rejected GetSSHPublicKey call must not have disturbed the key's status, "
        f"got {resp.get('Status')!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
