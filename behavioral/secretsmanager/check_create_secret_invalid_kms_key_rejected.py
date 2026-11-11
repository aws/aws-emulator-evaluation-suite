"""create-secret-invalid-kms-key-rejected."""
from __future__ import annotations

import re as _re

from behavioral_harness import tags

CHECK = "create-secret-invalid-kms-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSecret rejects a KmsKeyId referencing a well-formed but nonexistent KMS key
    ARN, leaves no secret behind under that name, and a secret created without a bogus key
    still succeeds normally.
    """
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_key_arn = f"arn:aws:kms:{ctx.region}:{account_id}:key/00000000-0000-0000-0000-000000000000"

    bad_name = ctx.unique_name("sim2real-behav-badkms-")
    # message varies: AWS embeds the downstream KMS call's per-request Request ID in it; the rest
    # is exact.
    code, message = _refusal(
        lambda: sm.create_secret(Name=bad_name, SecretString="x", KmsKeyId=bogus_key_arn)
    )
    # Secrets Manager validates the KmsKeyId parameter up front; a well-formed but
    # nonexistent key ARN is rejected as an invalid parameter value (empirically confirmed
    # against real AWS), not a generic "resource not found" for the CreateSecret call itself.
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert _re.fullmatch(_kms_refusal_pattern(bogus_key_arn), message or ""), (
        f"unexpected invalid-KMS-key message: {message!r}"
    )

    # Effect absent: no secret with that name was created.
    not_found_code, not_found_message = _refusal(lambda: sm.describe_secret(SecretId=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {not_found_code}"
    )
    assert not_found_message == "Secrets Manager can't find the specified secret.", (
        f"unexpected not-found message: {not_found_message!r}"
    )

    # Positive control: creating a secret without a bogus KmsKeyId still succeeds.
    good_name = ctx.unique_name("sim2real-behav-goodkms-")
    good = sm.create_secret(
        Name=good_name, SecretString="y", Tags=[{"Key": "sim2real-audit", "Value": "true"}]
    )
    good_arn = good["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=good_arn, ForceDeleteWithoutRecovery=True))

    # Terminal read is an independent DescribeSecret, not the CreateSecret response itself.
    described = sm.describe_secret(SecretId=good_arn)
    assert described["Name"] == good_name, f"expected {good_name!r}, got {described.get('Name')!r}"


def _refusal(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _kms_refusal_pattern(key_arn: str) -> str:
    """Secrets Manager's refusal of a nonexistent KMS key: KMS's own not-found text with its
    per-request Request ID, the one part that varies."""
    return (
        _re.escape(
            f"The operation failed because of an invalid KMS key: Key '{key_arn}' does not exist "
            "(Service: AWSKMS; Status Code: 400; Error Code: NotFoundException; Request ID: "
        )
        + "[0-9a-f-]+"
        + _re.escape("; Proxy: null)")
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
