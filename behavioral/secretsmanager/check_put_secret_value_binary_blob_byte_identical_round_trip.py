"""put-secret-value-binary-blob-byte-identical-round-trip."""
from __future__ import annotations

import hashlib
import os

from behavioral_harness import tags

CHECK = "put-secret-value-binary-blob-byte-identical-round-trip"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


def _digest(blob):
    """Short digest for diagnostics -- never put secret material in an assert message."""
    return f"sha256:{hashlib.sha256(blob).hexdigest()[:16]} len={len(blob)}"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A binary SecretBinary payload written via PutSecretValue is returned byte-for-byte
    identical (post base64 decode) on GetSecretValue."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-binsecret-")

    seed = os.urandom(64)
    sm.create_secret(
        Name=name,
        SecretBinary=seed,
        Tags=[{"Key": "sim2real", "Value": "behavioral-check"}],
    )
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    # A payload deliberately including bytes that are not valid utf-8 and edge byte values
    # (0x00, 0xff) to catch any text-coercion or truncation bugs in an emulator's storage path.
    payload = bytes([0x00, 0xFF, 0x7F, 0x80, 0x0A, 0x0D]) + os.urandom(4096)

    put_resp = sm.put_secret_value(SecretId=name, SecretBinary=payload)
    version_id = put_resp["VersionId"]

    got = sm.get_secret_value(SecretId=name, VersionId=version_id)
    assert got["SecretBinary"] == payload, (
        f"binary payload was not byte-identical on round trip: expected {_digest(payload)}, "
        f"got {_digest(got['SecretBinary'])}"
    )
    assert "SecretString" not in got, (
        "GetSecretValue on a binary-only version must OMIT SecretString, not return an "
        f"empty or coerced string; response keys were {sorted(got)}"
    )

    got_current = sm.get_secret_value(SecretId=name, VersionStage="AWSCURRENT")
    assert got_current["SecretBinary"] == payload, (
        f"AWSCURRENT binary payload mismatched: expected {_digest(payload)}, "
        f"got {_digest(got_current['SecretBinary'])}"
    )
    assert "SecretString" not in got_current, (
        "AWSCURRENT read of a binary-only version must OMIT SecretString; "
        f"response keys were {sorted(got_current)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
