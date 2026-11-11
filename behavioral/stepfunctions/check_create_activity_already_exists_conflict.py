"""create-activity-already-exists-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-activity-already-exists-conflict"
GROUP = 'activities'
SERVICES = ['stepfunctions']


def _create_kms_key(ctx):
    kms = ctx.client("kms")
    resp = kms.create_key(Description="sim2real-behav sfn test key", KeyUsage="ENCRYPT_DECRYPT")
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return resp["KeyMetadata"]["Arn"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _activities_named(sfn, name):
    """Every listed activity named name, across all ListActivities pages."""
    pages = sfn.get_paginator("list_activities").paginate()
    return [a for page in pages for a in page["activities"] if a["name"] == name]


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-creating an activity's name with a different encryptionConfiguration fails
    ActivityAlreadyExists with its exact message; ListActivities then lists exactly one activity
    with the name and DescribeActivity keeps the original encryption.
    """
    sfn = ctx.client("stepfunctions")
    key_arn = _create_kms_key(ctx)
    name = ctx.unique_name("sim2real-behav-act-conflict-")
    tags = [{"key": "sim2real", "value": "1"}]
    first = sfn.create_activity(name=name, tags=tags)
    ctx.on_cleanup(lambda a=first["activityArn"]: sfn.delete_activity(activityArn=a))

    code, message = _error(
        lambda: sfn.create_activity(
            name=name,
            tags=tags,
            encryptionConfiguration={
                "type": "CUSTOMER_MANAGED_KMS_KEY",
                "kmsKeyId": key_arn,
                "kmsDataKeyReusePeriodSeconds": 60,
            },
        )
    )
    assert code == "ActivityAlreadyExists", f"expected ActivityAlreadyExists, got {code}"
    assert message == f"Activity Already Exists: '{first['activityArn']}'", (
        f"unexpected ActivityAlreadyExists message {message!r}"
    )

    # Exactly one activity with this name must exist afterward, still on its original
    # (default AWS-owned) encryption — the rejected create must not have applied anything.
    # ListActivities is eventually consistent (sfn#ListActivities): poll until the name lists.
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
    assert len(matches) == 1, f"expected exactly 1 activity named {name!r} after rejected duplicate, got {matches}"

    described = sfn.describe_activity(activityArn=first["activityArn"])
    enc = described.get("encryptionConfiguration") or {}
    assert enc.get("type") != "CUSTOMER_MANAGED_KMS_KEY", (
        f"rejected create must not silently apply the new encryptionConfiguration, "
        f"got {described.get('encryptionConfiguration')!r}"
    )
    assert enc.get("kmsKeyId") != key_arn, (
        f"rejected create must not attach the KMS key it was rejected for, got {described.get('encryptionConfiguration')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
