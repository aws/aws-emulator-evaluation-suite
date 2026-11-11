"""hostkey-import-describe-delete-404."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "hostkey-import-describe-delete-404"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportHostKey registers a host key visible via Describe that 404s after Delete."""
    try:
        host_key_pem = _generate_ed25519_openssh_private_key()
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"], "module") from exc

    transfer = ctx.client("transfer")
    server_id = _create_server(ctx, transfer, Tags=[{"Key": "sim2real", "Value": CHECK}])
    description = ctx.unique_name("sim2real-hostkey-")

    resp = transfer.import_host_key(
        ServerId=server_id,
        HostKeyBody=host_key_pem,
        Description=description,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    host_key_id = resp["HostKeyId"]

    def _cleanup_hostkey():
        try:
            transfer.delete_host_key(ServerId=server_id, HostKeyId=host_key_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_hostkey)

    desc = transfer.describe_host_key(ServerId=server_id, HostKeyId=host_key_id)["HostKey"]
    assert desc["HostKeyId"] == host_key_id, f"expected HostKeyId {host_key_id}, got {desc.get('HostKeyId')}"
    assert desc["Description"] == description, (
        f"expected Description {description!r}, got {desc.get('Description')!r}"
    )

    transfer.delete_host_key(ServerId=server_id, HostKeyId=host_key_id)

    code, message = _error(lambda: transfer.describe_host_key(ServerId=server_id, HostKeyId=host_key_id))
    assert code == "ResourceNotFoundException", f"expected 404 after delete, got {code}"
    assert message == "Unknown host key", f"unexpected not-found message: {message!r}"

    remaining_ids = {hk["HostKeyId"] for hk in transfer.list_host_keys(ServerId=server_id)["HostKeys"]}
    assert host_key_id not in remaining_ids, (
        f"deleted host key {host_key_id} still listed by ListHostKeys: {remaining_ids}"
    )

    redelete_code, redelete_message = _error(
        lambda: transfer.delete_host_key(ServerId=server_id, HostKeyId=host_key_id)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected 404 re-deleting an already-deleted host key, got {redelete_code}"
    )
    assert redelete_message == "Unknown host key", f"unexpected not-found message: {redelete_message!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
