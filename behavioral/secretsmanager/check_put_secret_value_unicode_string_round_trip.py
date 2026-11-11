"""put-secret-value-unicode-string-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-secret-value-unicode-string-round-trip"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SecretString containing multi-byte unicode (emoji, CJK, combining marks) survives
    PutSecretValue/GetSecretValue unchanged."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-unisecret-")

    sm.create_secret(Name=name, SecretString="seed", Tags=[{"Key": "env", "Value": "test"}])
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    # Emoji (surrogate pair in UTF-16, 4 bytes in UTF-8), CJK ideographs, and a combining
    # diacritic mark (NFC-sensitive) -- any of these breaks under naive byte/codepoint handling.
    unicode_value = "caf\u00e9 \u4f60\u597d \U0001F600 e\u0301 \u0928\u092e\u0938\u094d\u0924\u0947"

    put_resp = sm.put_secret_value(SecretId=name, SecretString=unicode_value)
    version_id = put_resp["VersionId"]

    got = sm.get_secret_value(SecretId=name, VersionId=version_id)
    assert got["SecretString"] == unicode_value, "unicode string mutated on round trip"
    assert len(got["SecretString"]) == len(unicode_value), "unicode string length changed"

    got_current = sm.get_secret_value(SecretId=name, VersionStage="AWSCURRENT")
    assert got_current["SecretString"] == unicode_value, "AWSCURRENT unicode string mismatched"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
