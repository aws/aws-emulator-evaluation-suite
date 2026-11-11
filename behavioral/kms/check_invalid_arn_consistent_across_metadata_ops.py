"""invalid-arn-consistent-across-metadata-ops."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-arn-consistent-across-metadata-ops"
GROUP = "error-semantics"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A real key's ARN with a non-numeric account id is denied with AccessDeniedException by
    GetKeyLastUsage, ListKeyPolicies and UpdatePrimaryRegion alike, while the well-formed ARN
    gets past authorization (UpdatePrimaryRegion then fails only because the key is single-Region).
    """
    kms = ctx.client("kms")
    created = kms.create_key(
        Description=ctx.unique_name("sim2real-invalid-arn-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-invalid-arn-consistent"}],
    )
    key_id = created["KeyMetadata"]["KeyId"]
    valid_arn = created["KeyMetadata"]["Arn"]
    account_id = valid_arn.split(":")[4]
    ctx.on_cleanup(lambda: _best_effort_schedule_deletion(kms, key_id))

    # Only the account id is malformed (KMS ARNs require a 12-digit numeric account id).
    malformed_arn = valid_arn.replace(f":{account_id}:", ":notanumericaccount:")
    other_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"

    # Authorization denies before any op-specific lookup or ARN-shape validation runs.
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    def _denied(action):
        return (
            f"User: {caller_arn} is not authorized to perform: kms:{action} on this resource "
            "because the resource does not exist in this Region, no resource-based policies "
            "allow access, or a resource-based policy explicitly denies access"
        )

    code_last_usage, message_last_usage = _error(lambda: kms.get_key_last_usage(KeyId=malformed_arn))
    assert code_last_usage == "AccessDeniedException", f"unexpected error code: {code_last_usage!r}"
    assert message_last_usage == _denied("GetKeyLastUsage"), message_last_usage

    code_list_policies, message_list_policies = _error(lambda: kms.list_key_policies(KeyId=malformed_arn))
    assert code_list_policies == "AccessDeniedException", f"unexpected error code: {code_list_policies!r}"
    assert message_list_policies == _denied("ListKeyPolicies"), message_list_policies

    code_update_primary, message_update_primary = _error(
        lambda: kms.update_primary_region(KeyId=malformed_arn, PrimaryRegion=other_region)
    )
    assert code_update_primary == "AccessDeniedException", f"unexpected error code: {code_update_primary!r}"
    assert message_update_primary == _denied("UpdatePrimaryRegion"), message_update_primary


    # The rejected calls left the real key untouched.
    unaffected = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert unaffected["KeyState"] == "Enabled", f"unexpected KeyState: {unaffected['KeyState']!r}"
    assert unaffected["MultiRegion"] is False, f"unexpected MultiRegion: {unaffected['MultiRegion']!r}"

    # The well-formed ARN gets past authorization on all three.
    last_usage = kms.get_key_last_usage(KeyId=valid_arn)
    assert last_usage["KeyId"] == key_id, f"expected KeyId {key_id!r}, got {last_usage['KeyId']!r}"

    policies = kms.list_key_policies(KeyId=valid_arn)
    assert "default" in policies["PolicyNames"], f"expected 'default' in {policies['PolicyNames']!r}"

    code_update_primary_valid, message_update_primary_valid = _error(
        lambda: kms.update_primary_region(KeyId=valid_arn, PrimaryRegion=other_region)
    )
    assert code_update_primary_valid == "UnsupportedOperationException", (
        f"expected UnsupportedOperationException, got {code_update_primary_valid!r}"
    )
    assert message_update_primary_valid == f"{valid_arn} is not a multi-region key.", (
        message_update_primary_valid
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_schedule_deletion(kms, key_id):
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
