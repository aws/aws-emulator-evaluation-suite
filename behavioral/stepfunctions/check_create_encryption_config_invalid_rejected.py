"""create-encryption-config-invalid-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-encryption-config-invalid-rejected"
GROUP = 'activities'
SERVICES = ['stepfunctions']


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _create_kms_key(ctx, description="sim2real-behav sfn test key"):
    kms = ctx.client("kms")
    resp = kms.create_key(
        Description=description,
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": "1"}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return resp["KeyMetadata"]["Arn"]


def _lists_activity(sfn, name):
    paginator = sfn.get_paginator("list_activities")
    for page in paginator.paginate():
        if any(a["name"] == name for a in page["activities"]):
            return True
    return False


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateActivity with type CUSTOMER_MANAGED_KMS_KEY and no kmsKeyId fails with
    InvalidEncryptionConfiguration and the exact message and creates nothing, while the same call with
    a valid kmsKeyId creates the activity."""
    sfn = ctx.client("stepfunctions")
    tags = [{"key": "sim2real", "value": "1"}]

    # Positive control: the same request shape, but with a valid kmsKeyId, must succeed.
    key_arn = _create_kms_key(ctx)
    good_name = ctx.unique_name("sim2real-behav-act-goodenc-")
    good_arn = sfn.create_activity(
        name=good_name,
        encryptionConfiguration={"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_arn},
        tags=tags,
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=good_arn))
    assert _lists_activity(sfn, good_name), (
        f"expected the positive-control activity {good_name!r} to be created and listed"
    )

    bad_name = ctx.unique_name("sim2real-behav-act-badenc-")
    code, message = _error(
        lambda: sfn.create_activity(
            name=bad_name,
            encryptionConfiguration={"type": "CUSTOMER_MANAGED_KMS_KEY"},
            tags=tags,
        )
    )
    assert code == "InvalidEncryptionConfiguration", f"expected InvalidEncryptionConfiguration, got {code}"
    assert message == "Invalid Encryption Configuration: Must set a valid kmsKeyId.", (
        f"unexpected InvalidEncryptionConfiguration message {message!r}"
    )

    assert not _lists_activity(sfn, bad_name), "a rejected CreateActivity must not create anything"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
