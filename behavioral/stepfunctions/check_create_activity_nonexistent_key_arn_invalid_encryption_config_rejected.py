"""create-activity-nonexistent-key-arn-invalid-encryption-config-rejected."""
from __future__ import annotations

import re
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-activity-nonexistent-key-arn-invalid-encryption-config-rejected"
GROUP = "activities"
SERVICES = ["stepfunctions"]

# The relayed KMS message ends with the inner KMS call's request id and the SDK attempt count;
# those are the only parts that vary per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"SDK Attempt Count: [0-9]+")


def _stable(message):
    if message is None:
        return None
    return _ATTEMPTS.sub("SDK Attempt Count: <n>", _REQUEST_ID.sub("Request ID: <request-id>", message))


def _error(fn):
    """Call fn(); return its (code, message), the message stabilized. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), _stable(err.get("Message"))
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _lists_activity(sfn, name):
    paginator = sfn.get_paginator("list_activities")
    for page in paginator.paginate():
        if any(a["name"] == name for a in page["activities"]):
            return True
    return False


def _poll_lists_activity(sfn, name, want, timeout_s=30.0, interval_s=2.0):
    """Poll ListActivities for ``name``'s presence to equal ``want``; a sibling suite's own
    concurrent activity traffic can delay propagation past a single read."""
    deadline = time.monotonic() + timeout_s
    seen = _lists_activity(sfn, name)
    while seen != want and time.monotonic() < deadline:
        time.sleep(interval_s)
        seen = _lists_activity(sfn, name)
    return seen


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateActivity whose kmsKeyId names a key ARN that does not exist fails
    InvalidEncryptionConfiguration, not a KMS not-found code, and creates nothing.
    """
    sfn = ctx.client("stepfunctions")

    nonexistent_key_arn = f"arn:aws:kms:{ctx.region}:{ctx.account}:key/{uuid.uuid4()}"

    bad_name = ctx.unique_name("sim2real-behav-act-nokeyarn-")
    code, message = _error(
        lambda: sfn.create_activity(
            name=bad_name,
            encryptionConfiguration={"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": nonexistent_key_arn},
            tags=[{"key": "sim2real", "value": "true"}],
        )
    )
    assert code == "InvalidEncryptionConfiguration", (
        f"expected InvalidEncryptionConfiguration for a nonexistent key ARN, got {code!r} ({message!r})"
    )
    expected = (
        f"Key {nonexistent_key_arn!r} does not exist (Service: Kms, Status Code: 400, "
        "Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert not _poll_lists_activity(sfn, bad_name, False), (
        f"a rejected CreateActivity must not create anything, but {bad_name!r} is listed"
    )

    # Positive control: the same request shape, but with a key ARN that actually exists.
    kms = ctx.client("kms")
    real_key_arn = kms.create_key(
        Description="sim2real-behav-sfn-act-nokeyarn",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "true"}],
    )["KeyMetadata"]["Arn"]
    key_id = real_key_arn.rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # A key created moments ago can still read as nonexistent to CreateActivity's own
    # validation while it propagates; retry only that specific, expected-to-clear error.
    good_name = ctx.unique_name("sim2real-behav-act-realkeyarn-")
    deadline = time.monotonic() + 180.0
    good_arn = None
    last_message = None
    while good_arn is None and time.monotonic() < deadline:
        try:
            good_arn = sfn.create_activity(
                name=good_name,
                encryptionConfiguration={"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": real_key_arn},
                tags=[{"key": "sim2real", "value": "true"}],
            )["activityArn"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "InvalidEncryptionConfiguration" or "does not exist" not in (err.get("Message") or ""):
                raise
            last_message = err.get("Message")
            time.sleep(3.0)
    assert good_arn is not None, f"positive control never succeeded within 180s, last message: {last_message!r}"
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=good_arn))
    assert _poll_lists_activity(sfn, good_name, True), (
        f"expected the positive-control activity {good_name!r} to be created and listed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
