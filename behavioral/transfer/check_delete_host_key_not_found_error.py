"""delete-host-key-not-found-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-host-key-not-found-error"
GROUP = "error-semantics"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteHostKey on an already-deleted (or unknown) host key id returns
    ResourceNotFoundException, not InvalidRequestException, and a subsequent
    delete of a still-live key (positive control) still succeeds."""
    transfer = ctx.client("transfer")

    server_id = transfer.create_server(
        Protocols=["SFTP"], Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    key_a = _generate_ssh_private_key(ctx)
    key_b = _generate_ssh_private_key(ctx)

    host_key_a = transfer.import_host_key(
        ServerId=server_id, HostKeyBody=key_a, Description="key-a"
    )["HostKeyId"]
    host_key_b = transfer.import_host_key(
        ServerId=server_id, HostKeyBody=key_b, Description="key-b"
    )["HostKeyId"]

    # Delete key A once -- should succeed.
    transfer.delete_host_key(ServerId=server_id, HostKeyId=host_key_a)

    # Deleting the *same* (now-gone) host key id again must be ResourceNotFoundException.
    code, message = _error(lambda: transfer.delete_host_key(ServerId=server_id, HostKeyId=host_key_a))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Unknown host key", f"unexpected not-found message: {message!r}"

    # The deleted key must actually be gone (effect absent, not resurrected).
    remaining_ids = {hk["HostKeyId"] for hk in transfer.list_host_keys(ServerId=server_id)["HostKeys"]}
    assert host_key_a not in remaining_ids, f"deleted host key {host_key_a} still listed: {remaining_ids}"

    # Positive control: a still-live host key can still be deleted successfully.
    transfer.delete_host_key(ServerId=server_id, HostKeyId=host_key_b)
    remaining_ids_after = {
        hk["HostKeyId"] for hk in transfer.list_host_keys(ServerId=server_id)["HostKeys"]
    }
    assert host_key_b not in remaining_ids_after, (
        f"deleted host key {host_key_b} still listed: {remaining_ids_after}"
    )


def _error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _generate_ssh_private_key(ctx) -> str:
    """Generate a fresh RSA host private key in PEM (PKCS1) form using the
    cryptography library -- avoids any dependency on an external ssh-keygen
    binary being present in the execution environment."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
