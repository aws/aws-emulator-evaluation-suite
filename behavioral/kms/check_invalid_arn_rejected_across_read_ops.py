"""invalid-arn-rejected-across-read-ops."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "invalid-arn-rejected-across-read-ops"
GROUP = "error-semantics"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A malformed account-scoped key ARN gives NotFoundException from GetKeyLastUsage and
    ListKeyPolicies, a malformed principal ARN gives InvalidArnException from ListRetirableGrants,
    and all three succeed with well-formed values.
    """
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    account = sts.get_caller_identity()["Account"]
    # No resource field at all. With the caller's own account, KMS resolves malformed key
    # ARNs to NotFoundException rather than InvalidArnException.
    malformed_key_arn = f"arn:aws:kms:{ctx.region}:{account}"
    # The caller's own account avoids a cross-account AccessDeniedException; the resource
    # segment lacks a "role/" or "user/" prefix, which fails principal-ARN grammar.
    malformed_principal = f"arn:aws:iam::{account}:this-is-not-a-valid-iam-resource-segment"

    code_retirable, message_retirable = _error(
        lambda: kms.list_retirable_grants(RetiringPrincipal=malformed_principal)
    )
    assert code_retirable == "InvalidArnException", (
        f"ListRetirableGrants with a structurally malformed principal ARN returned "
        f"{code_retirable!r}, expected InvalidArnException"
    )
    assert message_retirable == f"ARN is not valid: {malformed_principal}", message_retirable

    code_last_usage, message_last_usage = _error(
        lambda: kms.get_key_last_usage(KeyId=malformed_key_arn)
    )
    assert code_last_usage == "NotFoundException", (
        f"GetKeyLastUsage with an unresolvable-but-account-scoped KeyId returned "
        f"{code_last_usage!r}, expected NotFoundException"
    )
    assert message_last_usage == f"Invalid arn {malformed_key_arn}", message_last_usage

    code_policies, message_policies = _error(lambda: kms.list_key_policies(KeyId=malformed_key_arn))
    assert code_policies == "NotFoundException", (
        f"ListKeyPolicies with an unresolvable-but-account-scoped KeyId returned "
        f"{code_policies!r}, expected NotFoundException"
    )
    assert message_policies == f"Invalid arn {malformed_key_arn}", message_policies

    # The same three operations succeed against real, well-formed values.
    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-arn-check-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "invalid-arn-rejected-across-read-ops"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    usage = kms.get_key_last_usage(KeyId=key_id)
    assert usage["KeyId"] == key_id, (
        f"positive control: GetKeyLastUsage on the real key returned KeyId "
        f"{usage['KeyId']!r}, expected {key_id!r}"
    )

    policies = kms.list_key_policies(KeyId=key_id)
    assert "default" in policies["PolicyNames"], (
        f'positive control: ListKeyPolicies on the real key returned '
        f'{policies["PolicyNames"]!r}, expected "default" to be present'
    )

    account = sts.get_caller_identity()["Account"]
    root_principal = f"arn:aws:iam::{account}:root"
    retirable = kms.list_retirable_grants(RetiringPrincipal=root_principal)
    assert "Grants" in retirable, (
        f"positive control: ListRetirableGrants with a well-formed root principal ARN "
        f"returned {retirable!r}, expected a 'Grants' key"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
