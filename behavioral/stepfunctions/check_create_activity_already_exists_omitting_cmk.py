"""create-activity-already-exists-omitting-cmk."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-activity-already-exists-omitting-cmk"
GROUP = "activities"
SERVICES = ["stepfunctions"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _activities_named(sfn, name):
    pages = sfn.get_paginator("list_activities").paginate()
    return [a for page in pages for a in page["activities"] if a["name"] == name]


def _refusal(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-creating a CMK-encrypted activity's name with no encryptionConfiguration at all
    fails ActivityAlreadyExists with its exact message: omitting the field is not read as a
    request to revert to AWS-owned encryption, and DescribeActivity keeps the original CMK.
    """
    sfn = ctx.client("stepfunctions")
    kms = ctx.client("kms")

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-sfn-act-omit-cmk-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "activity-omit-cmk"}],
    )["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    name = ctx.unique_name("sim2real-behav-act-omit-cmk-")
    encryption = {
        "type": "CUSTOMER_MANAGED_KMS_KEY",
        "kmsKeyId": key_id,
        "kmsDataKeyReusePeriodSeconds": 300,
    }
    first = sfn.create_activity(
        name=name, tags=[{"key": "sim2real", "value": "activity-omit-cmk"}],
        encryptionConfiguration=encryption,
    )
    activity_arn = first["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))

    baseline = sfn.describe_activity(activityArn=activity_arn).get("encryptionConfiguration")
    assert baseline.get("type") == "CUSTOMER_MANAGED_KMS_KEY" and baseline.get("kmsKeyId") == key_arn, (
        f"the activity was not created with its CMK encryptionConfiguration ({baseline!r}), so "
        "the rest of this check would grade nothing"
    )

    # Same name, now OMITTING encryptionConfiguration entirely -> must be rejected, not
    # silently accepted as a request to revert to the default (AWS-owned) encryption.
    code, message = _refusal(lambda: sfn.create_activity(name=name))
    assert code == "ActivityAlreadyExists", f"expected ActivityAlreadyExists, got {code!r}"
    expected_message = f"Activity Already Exists: '{activity_arn}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # ListActivities is eventually consistent; poll until the name lists exactly once.
    timeout_s = 60.0
    budget_s = _budget_s(ctx, timeout_s)
    start = time.monotonic()
    stop = start + min(timeout_s, budget_s)
    matches = _activities_named(sfn, name)
    while not matches and time.monotonic() < stop:
        time.sleep(2.0)
        matches = _activities_named(sfn, name)
    if not matches and budget_s < timeout_s:
        raise TimeoutError(
            f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
            f"{timeout_s}s ListActivities wait ended; not graded"
        )
    assert len(matches) == 1, f"expected exactly 1 activity named {name!r}, got {matches}"

    after = sfn.describe_activity(activityArn=activity_arn).get("encryptionConfiguration")
    assert after == baseline, (
        f"the rejected omit-CMK create must not revert or alter the encryptionConfiguration: "
        f"before={baseline!r} after={after!r}"
    )

    # Positive control: replaying the SAME (matching) encryptionConfiguration is still
    # idempotent and returns the same ARN, so the rejection above is about the mismatch, not
    # about naming collisions in general.
    replay = sfn.create_activity(name=name, encryptionConfiguration=encryption)
    assert replay["activityArn"] == activity_arn, (
        f"idempotent replay with the matching encryptionConfiguration returned a different ARN: "
        f"{replay['activityArn']!r} != {activity_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
