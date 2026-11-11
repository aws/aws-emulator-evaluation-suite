"""host-key-added-timestamp-precision-preserved."""
from __future__ import annotations

import datetime as dt
import time

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "host-key-added-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeHostKey returns a fixed DateImported for an imported host key.

    The value is a timestamp, identical across about 3 s of repeated reads, and within 5 s of the
    runner's clock around the ImportHostKey call. Sub-second precision is not checked.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"], "module") from exc

    transfer = ctx.client("transfer")
    server_id = _create_minimal_server(ctx)

    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    before_import = dt.datetime.now(dt.timezone.utc)
    resp = transfer.import_host_key(ServerId=server_id, HostKeyBody=pem, Description="sim2real host key")
    host_key_id = resp["HostKeyId"]
    ctx.on_cleanup(lambda: transfer.delete_host_key(ServerId=server_id, HostKeyId=host_key_id))
    after_import = dt.datetime.now(dt.timezone.utc)

    first = transfer.describe_host_key(ServerId=server_id, HostKeyId=host_key_id)["HostKey"]["DateImported"]
    assert isinstance(first, dt.datetime), f"DateImported should be a timestamp, got {type(first)!r}"

    # Poll repeatedly over a bounded window, failing fast the moment a sample
    # deviates, instead of sleeping blind and comparing only once at the end.
    _poll_stable(
        lambda: transfer.describe_host_key(ServerId=server_id, HostKeyId=host_key_id)["HostKey"]["DateImported"],
        expected=first,
        timeout_s=3.0,
        interval_s=0.5,
    )

    window_start = before_import - dt.timedelta(seconds=5)
    window_end = after_import + dt.timedelta(seconds=5)
    assert window_start <= first <= window_end, (
        f"DateImported {first!r} is not within the actual import window "
        f"[{window_start!r}, {window_end!r}]"
    )


def _poll_stable(probe, *, expected, timeout_s: float, interval_s: float) -> int:
    """Sample `probe()` repeatedly for up to `timeout_s`, asserting each sample
    still equals `expected`. Fails fast the moment a sample deviates, rather
    than sleeping for the whole window and only comparing once at the end."""
    deadline = time.monotonic() + timeout_s
    samples = 0
    while time.monotonic() < deadline:
        value = probe()
        assert value == expected, (
            f"DateImported changed after {samples} stable sample(s) "
            f"({expected!r} -> {value!r}); it must be a persisted value fixed at import "
            "time, not resampled on every read"
        )
        samples += 1
        time.sleep(interval_s)
    assert samples >= 1, "no samples were collected within the polling window"
    return samples


def _create_minimal_server(ctx) -> str:
    transfer = ctx.client("transfer")
    resp = transfer.create_server(
        EndpointType="PUBLIC",
        IdentityProviderType="SERVICE_MANAGED",
        Protocols=["SFTP"],
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    server_id = resp["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))
    return server_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
