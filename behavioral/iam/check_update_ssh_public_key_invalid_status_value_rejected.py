"""update-ssh-public-key-invalid-status-value-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-ssh-public-key-invalid-status-value-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSSHPublicKey rejects a Status value other than Active/Inactive with
    ValidationError (server-side enum-constraint validation), leaving the key's status
    unchanged, while a legitimate transition still succeeds."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-sshuser-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    ssh_pub, _pem_pub = _generate_rsa_ssh_and_pem_pubkeys()
    uploaded = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=ssh_pub)[
        "SSHPublicKey"
    ]
    key_id = uploaded["SSHPublicKeyId"]
    ctx.on_cleanup(lambda: iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id))
    assert uploaded["Status"] == "Active", f"expected freshly-uploaded key Active, got {uploaded['Status']!r}"

    code, message = _error(
        lambda: iam.update_ssh_public_key(
            UserName=user_name, SSHPublicKeyId=key_id, Status="Disabled"
        )
    )
    assert code == "ValidationError", repr(code)
    expected = "1 validation error detected: Value at 'status' failed to satisfy constraint: Member must satisfy enum value set: [Expired, Active, Inactive]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: status is unchanged by the rejected update
    current = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"][0]
    assert current["Status"] == "Active", (
        f"rejected UpdateSSHPublicKey must not change status, got {current['Status']!r}"
    )

    # positive control: a legitimate Active -> Inactive transition still works
    iam.update_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id, Status="Inactive")
    updated = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"][0]
    assert updated["Status"] == "Inactive", f"expected legitimate transition to Inactive, got {updated['Status']!r}"


def _error(fn):
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
