"""untag-resource-nonexistent-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-key-rejected"
GROUP = "tags"
SERVICES = ["kms"]

FAKE_KEY_ID = "00000000-0000-0000-0000-000000000000"


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource against a non-existent key id fails NotFoundException; the identical call
    against a real, tagged key in the same account succeeds and removes the tag."""
    kms = ctx.client("kms")

    # positive control: the identical operation, same account, against a real tagged key succeeds
    created = kms.create_key(
        Description=ctx.unique_name("kms-untag-notfound-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real-remove", "TagValue": "yes"}],
    )["KeyMetadata"]
    key_id, key_arn = created["KeyId"], created["Arn"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    code, message = _error(lambda: kms.untag_resource(KeyId=FAKE_KEY_ID, TagKeys=["sim2real-remove"]))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    arn_prefix = key_arn.rsplit(":", 1)[0]  # arn:aws:kms:<region>:<account>
    expected_message = f"Key '{arn_prefix}:key/{FAKE_KEY_ID}' does not exist"
    assert message == expected_message, f"unexpected message {message!r}"

    kms.untag_resource(KeyId=key_id, TagKeys=["sim2real-remove"])
    remaining = {t["TagKey"]: t["TagValue"] for t in kms.list_resource_tags(KeyId=key_id)["Tags"]}
    assert "sim2real-remove" not in remaining, (
        f"positive control: expected sim2real-remove to be gone after UntagResource, tags now {remaining}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
