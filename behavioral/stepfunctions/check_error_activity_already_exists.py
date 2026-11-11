"""error-activity-already-exists."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-activity-already-exists"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateActivity is idempotent on `name` only for MATCHING config; a second call with the
    same name but a *different* EncryptionConfiguration must fail with ActivityAlreadyExists
    instead of silently succeeding (or silently updating the encryption settings)."""
    sfn = ctx.client("stepfunctions")
    kms = ctx.client("kms")

    key = kms.create_key(
        Description="sim2real-behav-sfn-activity-cmk",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    name = ctx.unique_name("sim2real-behav-activity-")
    created = sfn.create_activity(name=name, tags=[{"key": "sim2real:managed", "value": "true"}])
    activity_arn = created["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))

    # Idempotent replay with the SAME (empty) config must succeed and return the same ARN.
    replay = sfn.create_activity(name=name)
    assert replay["activityArn"] == activity_arn, "idempotent CreateActivity replay returned a different ARN"

    baseline_encryption = sfn.describe_activity(activityArn=activity_arn).get("encryptionConfiguration")

    # Same name, but now with a genuinely different EncryptionConfiguration -> must be rejected.
    code, message = _refusal(
        lambda: sfn.create_activity(
            name=name,
            encryptionConfiguration={
                "type": "CUSTOMER_MANAGED_KMS_KEY",
                "kmsKeyId": key_id,
                "kmsDataKeyReusePeriodSeconds": 300,
            },
        )
    )
    assert code == "ActivityAlreadyExists", f"expected ActivityAlreadyExists, got {code!r}"
    expected_message = f"Activity Already Exists: '{activity_arn}'"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # Independent read at the destination: the rejected call must not have silently
    # applied (or partially applied) the CMK encryption configuration it was rejected for.
    after_encryption = sfn.describe_activity(activityArn=activity_arn).get("encryptionConfiguration")
    assert after_encryption == baseline_encryption, (
        f"ActivityAlreadyExists rejection still changed encryptionConfiguration: "
        f"before={baseline_encryption!r} after={after_encryption!r}"
    )


def _refusal(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises, so a target
    that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
