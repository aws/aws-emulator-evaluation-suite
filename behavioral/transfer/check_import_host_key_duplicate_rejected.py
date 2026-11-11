"""import-host-key-duplicate-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "import-host-key-duplicate-rejected"
GROUP = "overly-permissive"
SERVICES = ["transfer"]

try:
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _Encoding,
        NoEncryption as _NoEncryption,
        PrivateFormat as _PrivateFormat,
    )

    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-importing the exact same host key material for a server is rejected with
    ResourceExistsException instead of silently adding a duplicate host key."""

    if not _CRYPTO_AVAILABLE:
        raise RequiredToolMissing(["cryptography"], "module")

    transfer = ctx.client("transfer")

    server_id = transfer.create_server(Tags=[{"Key": "sim2real", "Value": CHECK}])["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    baseline_ids = {hk["HostKeyId"] for hk in transfer.list_host_keys(ServerId=server_id)["HostKeys"]}

    key1 = _generate_ssh_private_key()
    imported1 = transfer.import_host_key(
        ServerId=server_id,
        HostKeyBody=key1,
        Description="k1",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    host_key_id1 = imported1["HostKeyId"]
    ctx.on_cleanup(lambda: transfer.delete_host_key(ServerId=server_id, HostKeyId=host_key_id1))

    code, message = _error(
        lambda: transfer.import_host_key(ServerId=server_id, HostKeyBody=key1, Description="k1-dup")
    )
    assert code == "ResourceExistsException", f"expected ResourceExistsException, got {code!r}"
    assert message == "Host key already exists", f"unexpected duplicate-host-key message: {message!r}"

    # Effect absent: no duplicate host key was added alongside the original import.
    host_keys = transfer.list_host_keys(ServerId=server_id)["HostKeys"]
    ids_after_dup = {hk["HostKeyId"] for hk in host_keys}
    assert ids_after_dup == baseline_ids | {host_key_id1}, (
        f"expected only {baseline_ids | {host_key_id1}}, got {ids_after_dup}"
    )

    # Positive control: importing genuinely different key material succeeds.
    key2 = _generate_ssh_private_key()
    imported2 = transfer.import_host_key(
        ServerId=server_id,
        HostKeyBody=key2,
        Description="k2",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    host_key_id2 = imported2["HostKeyId"]
    ctx.on_cleanup(lambda: transfer.delete_host_key(ServerId=server_id, HostKeyId=host_key_id2))

    ids_after_second = {hk["HostKeyId"] for hk in transfer.list_host_keys(ServerId=server_id)["HostKeys"]}
    expected_after_second = baseline_ids | {host_key_id1, host_key_id2}
    assert ids_after_second == expected_after_second, (
        f"expected {expected_after_second} after importing a genuinely distinct key, "
        f"got {ids_after_second}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting the duplicate import is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected ImportHostKey to reject the duplicate, but it SUCCEEDED and returned {result!r}"
    )


def _generate_ssh_private_key() -> str:
    private_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=_Encoding.PEM,
        format=_PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=_NoEncryption(),
    ).decode()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

