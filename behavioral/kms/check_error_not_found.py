"""error-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-not-found"
GROUP = 'errors'
SERVICES = ['kms']

ERR_NOT_FOUND = "NotFoundException"

def _client_error(fn):
    """Call fn(); return its botocore Error. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

def _safe_schedule_delete(client, key_id):
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeKey on a non-existent key raises NotFoundException; the identical call against
    a real key in the same account succeeds, so the negative can't be confused with DescribeKey
    failing on every input."""
    kms = ctx.client("kms")
    fake_id = "00000000-0000-0000-0000-000000000000"
    err = _client_error(lambda: kms.describe_key(KeyId=fake_id))
    assert err["Code"] == ERR_NOT_FOUND, f"Expected {ERR_NOT_FOUND}, got {err!r}"

    # positive control: the same operation, same account, against a real key succeeds
    created = kms.create_key(
        Description=ctx.unique_name("kms-error-not-found-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-error-not-found"}],
    )["KeyMetadata"]
    key_id = created["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: _safe_schedule_delete(kms, _k))
    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert meta["KeyId"] == key_id, f"Expected KeyId {key_id!r}, got {meta['KeyId']!r}"

    # The refusal names the absent key's ARN; the account comes from the real key's ARN.
    account = created["Arn"].split(":")[4]
    expected = f"Key 'arn:aws:kms:{ctx.region}:{account}:key/{fake_id}' does not exist"
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
