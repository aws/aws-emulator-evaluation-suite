"""create-activity-kms-data-key-reuse-period-below-minimum-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-activity-kms-data-key-reuse-period-below-minimum-rejected"
GROUP = "activities"
SERVICES = ["stepfunctions", "kms"]

_MIN_REUSE_SECONDS = 60


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected CreateActivity to be refused, but it succeeded: {result!r}")


def _unvalidated_client(ctx):
    """A stepfunctions client with local parameter (range) validation disabled, so a value
    below the documented floor reaches the service instead of being rejected by botocore
    before it is sent."""
    from botocore.config import Config

    return ctx.client("stepfunctions", config=Config(parameter_validation=False))


def _create_key(ctx) -> str:
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description="sim2real-behav sfn activity encryption key",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": "1"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id


def _delete_activity(sfn, arn: str, timeout_s: float = 60.0) -> None:
    """Delete the activity, then read until it is gone, before its key's teardown runs."""
    sfn.delete_activity(activityArn=arn)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sfn.describe_activity(activityArn=arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ActivityDoesNotExist":
                return
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"{arn} still exists {timeout_s:g} s after DeleteActivity")
        time.sleep(2.0)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateActivity with kmsDataKeyReusePeriodSeconds one below the documented 60-second
    floor fails with ValidationException and the exact message and creates nothing, while
    the floor value itself is accepted and describable."""
    sfn = ctx.client("stepfunctions")
    sfn_raw = _unvalidated_client(ctx)
    key_id = _create_key(ctx)
    prefix = ctx.unique_name("sim2real-behav-act-")

    too_low = _MIN_REUSE_SECONDS - 1
    bad_name = f"{prefix}low"
    code, message = _error(lambda: sfn_raw.create_activity(
        name=bad_name,
        encryptionConfiguration={
            "type": "CUSTOMER_MANAGED_KMS_KEY",
            "kmsKeyId": key_id,
            "kmsDataKeyReusePeriodSeconds": too_low,
        },
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    expected = (
        f"1 validation error detected: Value '{too_low}' at "
        "'encryptionConfiguration.kmsDataKeyReusePeriodSeconds' failed to satisfy constraint: "
        "Member must have value greater than or equal to 60"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    paginator = sfn.get_paginator("list_activities")
    names = {a["name"] for page in paginator.paginate() for a in page["activities"]}
    assert bad_name not in names, f"a refused activity named {bad_name!r} is listed"

    good_name = f"{prefix}floor"
    good_arn = sfn.create_activity(
        name=good_name,
        encryptionConfiguration={
            "type": "CUSTOMER_MANAGED_KMS_KEY",
            "kmsKeyId": key_id,
            "kmsDataKeyReusePeriodSeconds": _MIN_REUSE_SECONDS,
        },
    )["activityArn"]
    ctx.on_cleanup(lambda: _delete_activity(sfn, good_arn))
    described = sfn.describe_activity(activityArn=good_arn)
    assert described["encryptionConfiguration"]["kmsDataKeyReusePeriodSeconds"] == _MIN_REUSE_SECONDS, (
        f"DescribeActivity returned {described['encryptionConfiguration']!r}, "
        f"expected kmsDataKeyReusePeriodSeconds={_MIN_REUSE_SECONDS}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
