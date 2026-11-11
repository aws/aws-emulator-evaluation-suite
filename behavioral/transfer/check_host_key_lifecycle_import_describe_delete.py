"""host-key-lifecycle-import-describe-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "host-key-lifecycle-import-describe-delete"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportHostKey attaches a key describable via DescribeHostKey; DeleteHostKey removes it and 404s after."""
    tf = ctx.client("transfer")
    server_id = _create_offline_server(ctx)
    host_key_body = _generate_ssh_host_key()
    description = ctx.unique_name("sim2real-hostkey-")

    resp = tf.import_host_key(
        ServerId=server_id,
        HostKeyBody=host_key_body,
        Description=description,
    )
    host_key_id = resp["HostKeyId"]
    ctx.on_cleanup(lambda: _safe_delete_host_key(tf, server_id, host_key_id))

    described = tf.describe_host_key(ServerId=server_id, HostKeyId=host_key_id)["HostKey"]
    assert described["HostKeyId"] == host_key_id, (
        f"expected HostKeyId {host_key_id!r}, got {described['HostKeyId']!r}"
    )
    assert described["Description"] == description, (
        f"expected Description {description!r}, got {described['Description']!r}"
    )

    tf.delete_host_key(ServerId=server_id, HostKeyId=host_key_id)
    code, message = _error(lambda: tf.describe_host_key(ServerId=server_id, HostKeyId=host_key_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    assert message == "Unknown host key", f"unexpected not-found message: {message!r}"


def _generate_ssh_host_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("ascii")


def _create_offline_server(ctx) -> str:
    tf = ctx.client("transfer")
    server_id = tf.create_server(
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ServerId"]
    ctx.on_cleanup(lambda: _safe_delete_server(tf, server_id))
    return server_id


def _safe_delete_server(tf, server_id: str) -> None:
    try:
        tf.delete_server(ServerId=server_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_host_key(tf, server_id: str, host_key_id: str) -> None:
    try:
        tf.delete_host_key(ServerId=server_id, HostKeyId=host_key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
