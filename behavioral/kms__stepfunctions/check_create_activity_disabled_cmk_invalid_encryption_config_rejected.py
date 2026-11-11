"""create-activity-disabled-cmk-invalid-encryption-config-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-activity-disabled-cmk-invalid-encryption-config-rejected"
GROUP = "activities"
SERVICES = ["kms", "stepfunctions"]

_EXPECTED_MESSAGE = "kmsKeyId is not enabled"


def _lists_activity(sfn, name):
    paginator = sfn.get_paginator("list_activities")
    for page in paginator.paginate():
        if any(a["name"] == name for a in page["activities"]):
            return True
    return False


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateActivity with a disabled customer managed KMS key fails InvalidEncryptionConfiguration,
    not a KMS-specific code, and creates nothing; the same call with the key re-enabled succeeds.
    """
    sfn = ctx.client("stepfunctions")
    kms = ctx.client("kms")

    key = kms.create_key(
        Description="sim2real-behav-sfn-act-disabledcmk",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "true"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    kms.disable_key(KeyId=key_id)
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key_id))
    state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"DisableKey must leave the key Disabled; it is {state!r}"

    def _try_create_bad(name: str):
        return sfn.create_activity(
            name=name,
            encryptionConfiguration={"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_id},
            tags=[{"key": "sim2real", "value": "true"}],
        )

    # The key state change itself takes a moment to propagate through KMS; poll for the
    # refusal rather than asserting on the very first sample. A call accepted during that
    # propagation window gets its cleanup registered, and the next attempt uses a fresh name so
    # the refused name is one nothing was ever created under.
    deadline = time.monotonic() + 60.0
    while True:
        bad_name = ctx.unique_name("sim2real-behav-act-disabledcmk-")
        try:
            accepted = _try_create_bad(bad_name)
        except ClientError as exc:
            err = exc.response["Error"]
            code, message = err["Code"], err.get("Message")
            if code != "InvalidEncryptionConfiguration":
                raise AssertionError(
                    f"expected InvalidEncryptionConfiguration for a disabled CMK, got {code!r} "
                    f"({message!r})") from exc
            break
        ctx.on_cleanup(lambda arn=accepted["activityArn"]: sfn.delete_activity(activityArn=arn))
        if time.monotonic() > deadline:
            raise AssertionError(
                "CreateActivity still accepted a disabled CMK 60s after DisableKey")
        time.sleep(3.0)
    assert message == _EXPECTED_MESSAGE, (
        f"unexpected InvalidEncryptionConfiguration message {message!r}"
    )
    assert not _lists_activity(sfn, bad_name), "a rejected CreateActivity must not create anything"

    # Positive control: the same request shape, but with the key re-enabled, must succeed.
    kms.enable_key(KeyId=key_id)
    state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state == "Enabled", f"EnableKey must leave the key Enabled; it is {state!r}"

    good_name = ctx.unique_name("sim2real-behav-act-enabledcmk-")
    deadline = time.monotonic() + 90.0
    good_arn = None
    last_error = None
    while good_arn is None and time.monotonic() < deadline:
        try:
            good_arn = sfn.create_activity(
                name=good_name,
                encryptionConfiguration={"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_id},
                tags=[{"key": "sim2real", "value": "true"}],
            )["activityArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidEncryptionConfiguration":
                raise
            last_error = exc.response["Error"]
            time.sleep(3.0)
    assert good_arn is not None, f"positive control never succeeded within 90s, last error: {last_error!r}"
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=good_arn))
    assert _lists_activity(sfn, good_name), (
        f"expected the positive-control activity {good_name!r} to be created and listed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
