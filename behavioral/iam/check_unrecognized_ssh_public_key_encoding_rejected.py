"""unrecognized-ssh-public-key-encoding-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unrecognized-ssh-public-key-encoding-rejected"
GROUP = 'errors'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _gen_ssh_rsa_public_key(key_bits=2048):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    public_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    return public_bytes.decode("ascii") + " sim2real-generated-key"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSSHPublicKey with an unknown Encoding and UpdateSSHPublicKey with an unknown Status are
    rejected with ValidationError and leave the key unchanged; a valid Status update succeeds."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    uploaded = iam.upload_ssh_public_key(
        UserName=user_name, SSHPublicKeyBody=_gen_ssh_rsa_public_key()
    )
    key_id = uploaded["SSHPublicKey"]["SSHPublicKeyId"]
    ctx.on_cleanup(lambda: iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id))

    code_get, message_get = _error(
        lambda: iam.get_ssh_public_key(
            UserName=user_name, SSHPublicKeyId=key_id, Encoding="BOGUS-ENCODING"
        )
    )
    assert code_get == "ValidationError", (
        f"GetSSHPublicKey: expected ValidationError for an unrecognized Encoding, got {code_get}"
    )
    expected = (
        "1 validation error detected: Value at 'encoding' failed to satisfy constraint: "
        "Member must satisfy enum value set: [SSH, PEM]"
    )
    assert message_get == expected, f"expected message {expected!r}, got {message_get!r}"

    # The rejected Get must not have disturbed the key: a valid Encoding still works.
    got = iam.get_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id, Encoding="SSH")
    assert got["SSHPublicKey"]["SSHPublicKeyId"] == key_id

    code_update, message_update = _error(
        lambda: iam.update_ssh_public_key(
            UserName=user_name, SSHPublicKeyId=key_id, Status="BogusStatus"
        )
    )
    assert code_update == "ValidationError", (
        f"UpdateSSHPublicKey: expected ValidationError for an invalid Status enum, "
        f"got {code_update}"
    )
    expected = (
        "1 validation error detected: Value at 'status' failed to satisfy constraint: "
        "Member must satisfy enum value set: [Expired, Active, Inactive]"
    )
    assert message_update == expected, f"expected message {expected!r}, got {message_update!r}"

    listed = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]
    status_after = next(k["Status"] for k in listed if k["SSHPublicKeyId"] == key_id)
    assert status_after == "Active", (
        f"a rejected UpdateSSHPublicKey must not have changed the key's status, got {status_after}"
    )

    # Positive control: the same call with a valid Status succeeds.
    iam.update_ssh_public_key(UserName=user_name, SSHPublicKeyId=key_id, Status="Inactive")
    listed_after_valid = iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]
    status_after_valid = next(
        k["Status"] for k in listed_after_valid if k["SSHPublicKeyId"] == key_id
    )
    assert status_after_valid == "Inactive", (
        f"a legitimate UpdateSSHPublicKey(Status='Inactive') should have taken effect, "
        f"got status {status_after_valid}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
