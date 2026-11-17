"""list-resource-tags-nonexistent-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resource-tags-nonexistent-key-rejected"
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
    """ListResourceTags against a non-existent key id fails NotFoundException; the identical
    call against a real, tagged key in the same account succeeds and returns its tag."""
    kms = ctx.client("kms")

    code, message = _error(lambda: kms.list_resource_tags(KeyId=FAKE_KEY_ID))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"

    # positive control: the same operation, same account, against a real tagged key succeeds
    created = kms.create_key(
        Description=ctx.unique_name("kms-listtags-notfound-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real-present", "TagValue": "yes"}],
    )["KeyMetadata"]
    key_id, key_arn = created["KeyId"], created["Arn"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    arn_prefix = key_arn.rsplit(":", 1)[0]  # arn:aws:kms:<region>:<account>
    expected_message = f"Key '{arn_prefix}:key/{FAKE_KEY_ID}' does not exist"
    assert message == expected_message, f"unexpected message {message!r}"

    tags_map = {t["TagKey"]: t["TagValue"] for t in kms.list_resource_tags(KeyId=key_id)["Tags"]}
    assert tags_map.get("sim2real-present") == "yes", (
        f"positive control: expected sim2real-present=yes, got {tags_map}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
