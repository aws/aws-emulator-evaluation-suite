"""imported-host-key-active-without-downtime-window."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "imported-host-key-active-without-downtime-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An imported host key is immediately visible in DescribeHostKey and ListHostKeys,
    while DescribeServer's top-level HostKeyFingerprint stays pinned to the original key."""
    transfer = ctx.client("transfer")

    server_id = transfer.create_server(
        Protocols=["SFTP"], Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    server_fingerprint_before = transfer.describe_server(ServerId=server_id)["Server"].get(
        "HostKeyFingerprint"
    )
    assert server_fingerprint_before, f"a new SFTP server reports no HostKeyFingerprint: {server_fingerprint_before!r}"

    key_body = _generate_ssh_private_key(ctx)
    imported = transfer.import_host_key(
        ServerId=server_id,
        HostKeyBody=key_body,
        Description="freshly-imported",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    host_key_id = imported["HostKeyId"]
    ctx.on_cleanup(lambda: transfer.delete_host_key(ServerId=server_id, HostKeyId=host_key_id))

    # No poll, no sleep: the very next calls must already see it as active.
    described = transfer.describe_host_key(ServerId=server_id, HostKeyId=host_key_id)["HostKey"]
    imported_fingerprint = described["HostKeyFingerprint"]
    expected_core = _sha256_fingerprint_core(key_body)
    assert _normalize_fingerprint(imported_fingerprint) == expected_core, (
        f"DescribeHostKey fingerprint {imported_fingerprint!r} is not the SHA256 of the imported "
        f"key's public blob (expected SHA256:{expected_core})"
    )
    assert described["HostKeyId"] == host_key_id, (
        f"expected HostKeyId {host_key_id!r} echoed back by DescribeHostKey, got "
        f"{described['HostKeyId']!r}"
    )

    listed = transfer.list_host_keys(ServerId=server_id)["HostKeys"]
    listed_ids = {hk["HostKeyId"] for hk in listed}
    assert host_key_id in listed_ids, (
        f"freshly imported host key {host_key_id!r} is not yet visible in "
        f"ListHostKeys {listed_ids!r} -- there IS a propagation-delay window"
    )
    listed_fingerprint = next(hk["Fingerprint"] for hk in listed if hk["HostKeyId"] == host_key_id)
    assert listed_fingerprint == imported_fingerprint, (
        "ListHostKeys reports a different fingerprint than DescribeHostKey for the "
        "same just-imported key -- no consistent immediate view"
    )

    server_fingerprint_after = transfer.describe_server(ServerId=server_id)["Server"].get(
        "HostKeyFingerprint"
    )
    assert server_fingerprint_after == server_fingerprint_before, (
        f"DescribeServer's top-level HostKeyFingerprint moved from "
        f"{server_fingerprint_before!r} to {server_fingerprint_after!r} immediately after "
        "ImportHostKey -- it is supposed to stay pinned to the server's original host key, "
        "not track the most recently imported one"
    )


def _sha256_fingerprint_core(private_pem: str) -> str:
    """The OpenSSH SHA256 fingerprint of a private key's public blob, base64 without padding."""
    import base64
    import hashlib

    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    openssh = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    blob = base64.b64decode(openssh.split()[1])
    return base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _normalize_fingerprint(value: str) -> str:
    """Compare fingerprints with or without the 'SHA256:' prefix and base64 padding."""
    return value.removeprefix("SHA256:").rstrip("=")


def _generate_ssh_private_key(ctx) -> str:
    """A fresh RSA host private key in PEM (PKCS1) form, without needing ssh-keygen."""
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
