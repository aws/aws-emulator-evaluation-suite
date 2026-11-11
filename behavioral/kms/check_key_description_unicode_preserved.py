"""key-description-unicode-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "key-description-unicode-preserved"
GROUP = "error-semantics"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateKeyDescription with unicode/emoji text is returned unchanged, byte-for-byte,
    by a subsequent DescribeKey - no normalization, truncation, or mojibake."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description="initial-ascii-description",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    unicode_description = (
        "Caf\u00e9 \u2615 \u65e5\u672c\u8a9e\u8aac\u660e "
        "\U0001f511\U0001f5dd\ufe0f \u041f\u0440\u0438\u0432\u0435\u0442 Ño\u00f1o"
    )
    kms.update_key_description(KeyId=key_id, Description=unicode_description)

    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Description"]
    assert described == unicode_description, "unicode description must round-trip byte-for-byte"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
