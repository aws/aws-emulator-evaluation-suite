"""key-description-empty-vs-absent-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "key-description-empty-vs-absent-preserved"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A key created without a Description reports Description ''; resetting a populated description
    via UpdateKeyDescription('') persists the same present, empty value.
    """
    kms = ctx.client("kms")

    never_set_key_id = kms.create_key()["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=never_set_key_id, PendingWindowInDays=7)
    )
    fresh_meta = kms.describe_key(KeyId=never_set_key_id)["KeyMetadata"]
    assert "Description" in fresh_meta, f"Description missing from KeyMetadata: {fresh_meta}"
    assert fresh_meta["Description"] == "", f"never-set description not default '': {fresh_meta!r}"

    populated_key_id = kms.create_key(Description="sim2real-original-description")[
        "KeyMetadata"
    ]["KeyId"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=populated_key_id, PendingWindowInDays=7)
    )
    populated_meta = kms.describe_key(KeyId=populated_key_id)["KeyMetadata"]
    assert populated_meta["Description"] == "sim2real-original-description", populated_meta[
        "Description"
    ]

    kms.update_key_description(KeyId=populated_key_id, Description="")
    updated_meta = kms.describe_key(KeyId=populated_key_id)["KeyMetadata"]
    assert "Description" in updated_meta, "explicit empty description did not persist as present"
    assert updated_meta["Description"] == "", updated_meta["Description"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
