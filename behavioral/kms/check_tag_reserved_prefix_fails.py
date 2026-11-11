"""tag-reserved-prefix-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-reserved-prefix-fails"
GROUP = 'tags'
SERVICES = ['kms']


def _err(fn):
    """Return the botocore Error (Code and Message) if fn() raises ClientError. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"Code": err.get("Code"), "Message": err.get("Message")}
    raise AssertionError(f"expected TagResource to be rejected, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Tagging a key with a reserved 'aws:' prefixed key must fail with TagException, leaving
    the key's tag set exactly as it was before the rejected call."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=ctx.unique_name("kms-tagreserved-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    # Positive control: an ordinary tag is accepted, proving the account/credentials/API are
    # otherwise healthy for TagResource before the negative is exercised.
    kms.tag_resource(KeyId=key_id, Tags=[{"TagKey": "sim2real-valid", "TagValue": "ok"}])

    err = _err(
        lambda: kms.tag_resource(
            KeyId=key_id, Tags=[{"TagKey": "aws:reserved", "TagValue": "nope"}]
        )
    )
    assert err["Code"] == "TagException", f"expected TagException, got {err!r}"
    assert err["Message"] == "Tags beginning with aws: are reserved", err

    # Independent read at the destination: the reserved tag was never applied, and the earlier
    # positive-control tag is untouched.
    tags_after = kms.list_resource_tags(KeyId=key_id)["Tags"]
    keys_after = {t["TagKey"]: t["TagValue"] for t in tags_after}
    assert "aws:reserved" not in keys_after, f"reserved tag was applied: {keys_after}"
    assert keys_after.get("sim2real-valid") == "ok", f"positive control lost: {keys_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
