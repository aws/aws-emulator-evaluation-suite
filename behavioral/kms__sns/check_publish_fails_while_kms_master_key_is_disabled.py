"""publish-fails-while-kms-master-key-is-disabled."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-fails-while-kms-master-key-is-disabled"
GROUP = 'overly-permissive'
SERVICES = ['kms', 'sns']

ERR_KMS_DISABLED = "KMSDisabled"
# SNS keeps a data key cached for about 300 s after DisableKey, so Publish keeps SUCCEEDING for
# about that long; the ceiling outlasts that cache with margin.
_DISABLE_CEILING_S = 420
# Re-enabling does not restore Publish at once (about 75 s after EnableKey); the ceiling gives
# that margin.
_RESTORE_CEILING_S = 180


#: What ``_err`` answers for a Publish that succeeded; never a code real AWS could return.
PUBLISHED = "<published>"


def _err(fn):
    """Return the ClientError's Error.Code, or PUBLISHED on success.

    A Publish that SUCCEEDS while the key is disabled is the over-permissive failure this check
    exists to catch, so success is named and never reads as merely the wrong code.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return PUBLISHED


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html
@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Publish to a topic encrypted with a customer-managed KMS key fails with exactly KMSDisabled
    once the key is disabled, and re-enabling the key restores Publish; a control Publish runs
    first, so a topic that refuses every Publish fails the control."""
    kms = ctx.client("kms")
    sns = ctx.client("sns")

    key_arn = kms.create_key(
        Description=ctx.unique_name("sim2real-xsvc-kmssns-dis-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]
    key_id = key_arn.split("/")[-1]
    # Registered first so LIFO runs it LAST: KMS has no immediate delete, and a key left disabled
    # by an aborted run would make the topic (deleted independently, below) a non-issue, but the
    # key itself must still end up scheduled for deletion either way.
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    # Registered second so it runs BEFORE the scheduled deletion: re-enabling is idempotent and
    # harmless even if the check already restored the key itself.
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key_id))

    alias_name = ctx.unique_name("alias/sim2real-xsvc-kmssns-dis-")
    kms.create_alias(AliasName=alias_name, TargetKeyId=key_id)
    ctx.on_cleanup(lambda: kms.delete_alias(AliasName=alias_name))

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-kmssns-dis-"),
        Attributes={"KmsMasterKeyId": alias_name},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    # --- control FIRST: the CMK-encrypted topic works before anything is broken ---------
    control = sns.publish(TopicArn=topic_arn, Message="control-before-disable")
    assert control.get("MessageId"), (
        f"the CMK-encrypted topic must accept Publish before the key is disabled, got {control}"
    )

    # --- break exactly one thing ----------------------------------------------------------
    kms.disable_key(KeyId=key_id)

    code = None
    deadline = time.monotonic() + _DISABLE_CEILING_S
    attempt = 0
    while True:
        attempt += 1
        code = _err(lambda: sns.publish(TopicArn=topic_arn, Message=f"probe-{attempt}"))
        if code != PUBLISHED or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert code == ERR_KMS_DISABLED, (
        f"Publish to a topic whose CMK is disabled must fail with {ERR_KMS_DISABLED!r} within "
        f"{_DISABLE_CEILING_S}s and {attempt} attempts; got {code!r} ({PUBLISHED!r} means every attempt "
        f"SUCCEEDED, i.e. the disabled key was never consulted at Publish time)"
    )

    # A second, independent call while still disabled: the refusal is not a one-off blip.
    still_denied = _err(lambda: sns.publish(TopicArn=topic_arn, Message="still-denied"))
    assert still_denied == ERR_KMS_DISABLED, (
        f"a second Publish while the key is still disabled must also fail with "
        f"{ERR_KMS_DISABLED!r}; got {still_denied!r}"
    )

    # --- repair the one broken thing; the refusal reverses --------------------------------
    kms.enable_key(KeyId=key_id)
    restored_code = "unattempted"
    restore_deadline = time.monotonic() + _RESTORE_CEILING_S
    while True:
        restored_code = _err(lambda: sns.publish(TopicArn=topic_arn, Message="restore-probe"))
        if restored_code == PUBLISHED or time.monotonic() >= restore_deadline:
            break
        time.sleep(2)
    assert restored_code == PUBLISHED, (
        f"re-enabling the CMK did not restore Publish within {_RESTORE_CEILING_S}s: still "
        f"{restored_code!r} -- the check cannot pass by refusing every Publish forever"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
