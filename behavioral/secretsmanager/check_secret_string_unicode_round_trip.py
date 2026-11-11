"""secret-string-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "secret-string-unicode-round-trip"
GROUP = "representation"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SecretString with multi-byte unicode is returned byte-identical by GetSecretValue."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-unicode-")
    secret_value = "héllo wörld — 世界 🎉 Zürich café ñoño Москва日本語"

    sm.create_secret(Name=name, SecretString=secret_value, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    resp = sm.get_secret_value(SecretId=name)
    assert resp["SecretString"] == secret_value, (
        f"expected {secret_value!r}, got {resp['SecretString']!r}"
    )

    # Independent second read through the explicit AWSCURRENT stage, not just the
    # SecretId-only default path, so a target that mishandles unicode only when
    # resolving a version stage does not slip through.
    current = sm.get_secret_value(SecretId=name, VersionStage="AWSCURRENT")
    assert current["SecretString"] == secret_value, (
        f"AWSCURRENT read expected {secret_value!r}, got {current['SecretString']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
