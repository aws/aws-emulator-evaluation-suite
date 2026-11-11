"""import-hostkey-duplicate-resource-exists-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "import-hostkey-duplicate-resource-exists-rejected"
GROUP = "error-semantics"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportHostKey twice with identical key material on the same server returns
    ResourceExistsException on the second call, the host key list is not double-counted,
    and importing a genuinely distinct key still succeeds (positive control)."""
    try:
        key1_pem = _generate_ed25519_openssh_private_key()
        key2_pem = _generate_ed25519_openssh_private_key()
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"], "module") from exc

    transfer = ctx.client("transfer")
    server_id = _create_server(ctx, transfer)

    key_id1 = transfer.import_host_key(ServerId=server_id, HostKeyBody=key1_pem)["HostKeyId"]

    def _cleanup_key1():
        try:
            transfer.delete_host_key(ServerId=server_id, HostKeyId=key_id1)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_key1)

    code, message = _err(lambda: transfer.import_host_key(ServerId=server_id, HostKeyBody=key1_pem))
    assert code == "ResourceExistsException", f"expected ResourceExistsException, got {code}"
    assert message == "Host key already exists", f"unexpected duplicate host key message {message!r}"

    # Effect absent: the duplicate attempt did not add a second entry for that key.
    keys = transfer.list_host_keys(ServerId=server_id)["HostKeys"]
    matching = [k for k in keys if k["HostKeyId"] == key_id1]
    assert len(matching) == 1, f"expected exactly one entry for the imported key, got {len(matching)}"

    # Positive control: a genuinely distinct key imports successfully.
    key_id2 = transfer.import_host_key(ServerId=server_id, HostKeyBody=key2_pem)["HostKeyId"]

    def _cleanup_key2():
        try:
            transfer.delete_host_key(ServerId=server_id, HostKeyId=key_id2)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_key2)

    assert key_id2 != key_id1, f"expected a distinct host key id, got {key_id2!r} again"

    # Terminal read at the destination, independent of the import calls: both keys are
    # actually visible, not just accepted.
    keys_after = transfer.list_host_keys(ServerId=server_id)["HostKeys"]
    ids_after = {k["HostKeyId"] for k in keys_after}
    assert {key_id1, key_id2} <= ids_after, (
        f"expected both {key_id1!r} and {key_id2!r} listed after the distinct import, got {ids_after}"
    )


def _err(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_server(ctx, transfer, **kwargs):
    server_id = transfer.create_server(**kwargs)["ServerId"]

    def _cleanup():
        try:
            transfer.delete_server(ServerId=server_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return server_id


def _generate_ed25519_openssh_private_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("ascii")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
