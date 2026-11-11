"""reserved-tag-prefix-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "reserved-tag-prefix-rejected"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a tag key with the reserved 'aws:' prefix (TagException), does not
    persist it, and leaves the key's existing valid tag unchanged."""
    kms = ctx.client("kms")
    key_id = kms.create_key(Description=ctx.unique_name("sim2real-kms-reservedtag-"))["KeyMetadata"][
        "KeyId"
    ]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # Positive control: an ordinary tag is accepted.
    kms.tag_resource(KeyId=key_id, Tags=[{"TagKey": "sim2real-valid-tag", "TagValue": "ok"}])

    code, message = _error(
        lambda: kms.tag_resource(
            KeyId=key_id, Tags=[{"TagKey": "aws:reserved-should-fail", "TagValue": "blocked"}]
        )
    )
    assert code == "TagException", f"expected TagException, got {code}"
    assert message == "Tags beginning with aws: are reserved", message

    tags_after = kms.list_resource_tags(KeyId=key_id)["Tags"]
    keys_after = {t["TagKey"] for t in tags_after}
    assert "aws:reserved-should-fail" not in keys_after, keys_after
    # Positive control still holds: the earlier valid tag persisted untouched.
    assert "sim2real-valid-tag" in keys_after, keys_after
    valid = next(t for t in tags_after if t["TagKey"] == "sim2real-valid-tag")
    assert valid["TagValue"] == "ok", valid


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected TagResource to reject the reserved-prefix tag, but it succeeded: {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
