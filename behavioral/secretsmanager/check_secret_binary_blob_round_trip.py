"""secret-binary-blob-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "secret-binary-blob-round-trip"
GROUP = "representation"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SecretBinary blob written via PutSecretValue is returned exactly, without re-encoding drift."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-binary-")

    # Deliberately non-UTF8-decodable bytes mixed with printable/unicode-encoded bytes, to
    # catch any implementation that treats SecretBinary as text under the hood.
    binary_blob = (
        b"\x00\x01\x02\xfe\xff"
        + "unicode-embedded: 世界 café".encode("utf-8")
        + bytes(range(200, 256))
    )

    # PutSecretValue requires the secret to already exist (unlike some SDK docs suggest);
    # on real AWS it raises ResourceNotFoundException for a brand-new name. So create the
    # secret first with a placeholder value, then add the real binary blob as a new version.
    sm.create_secret(
        Name=name,
        SecretString="placeholder-initial-version",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    put_resp = sm.put_secret_value(SecretId=name, SecretBinary=binary_blob)
    version_id = put_resp["VersionId"]

    resp = sm.get_secret_value(SecretId=name)
    assert resp["SecretBinary"] == binary_blob, (
        f"binary blob did not round-trip byte-identically: wrote {len(binary_blob)} bytes, "
        f"read back {resp.get('SecretBinary', b'')!r}"
    )
    assert resp["VersionId"] == version_id, (
        f"GetSecretValue's default (AWSCURRENT) read returned version {resp['VersionId']!r}, "
        f"expected the version PutSecretValue just minted: {version_id!r}"
    )
    assert "SecretString" not in resp, (
        "GetSecretValue on a binary-only version must omit SecretString entirely, not return "
        f"one alongside SecretBinary; response keys were {sorted(resp)}"
    )

    # An independent read through a different operation: DescribeSecret's own stage map must
    # agree with GetSecretValue about which version is current.
    described = sm.describe_secret(SecretId=name)
    assert described["VersionIdsToStages"].get(version_id) == ["AWSCURRENT"], (
        f"DescribeSecret must show version {version_id!r} holding exactly AWSCURRENT; got "
        f"{described['VersionIdsToStages'].get(version_id)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
