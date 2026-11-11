"""update-secret-invalid-kms-key-rejected."""
from __future__ import annotations

import re as _re

import time

from behavioral_harness import tags

CHECK = "update-secret-invalid-kms-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSecret rejects an attempt to change KmsKeyId to a well-formed but nonexistent
    KMS key ARN, leaves the secret's existing KmsKeyId unchanged, and an unrelated update
    (Description) on the same secret still succeeds.
    """
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-updkms-")
    secret = sm.create_secret(
        Name=name,
        SecretString="original-value",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    original_kms = sm.describe_secret(SecretId=arn).get("KmsKeyId")

    bogus_key_arn = f"arn:aws:kms:{ctx.region}:{account_id}:key/00000000-0000-0000-0000-000000000000"
    code, message = _error_code(lambda: sm.update_secret(SecretId=arn, KmsKeyId=bogus_key_arn))
    # UpdateSecret validates the KmsKeyId parameter up front; a well-formed but nonexistent
    # key ARN is rejected as an invalid parameter value.
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    # message varies: it embeds the downstream KMS call's per-request Request ID; the rest is exact.
    assert _re.fullmatch(_kms_refusal_pattern(bogus_key_arn), message or ""), (
        f"unexpected invalid-KMS-key message: {message!r}"
    )

    # Effect absent: KmsKeyId on the secret is unchanged by the rejected call.
    after = sm.describe_secret(SecretId=arn)
    after_kms = after.get("KmsKeyId")
    assert after_kms == original_kms, (
        f"expected KmsKeyId to remain {original_kms!r} after the rejected update, got {after_kms!r}"
    )

    # Positive control: an unrelated field update on the same secret still succeeds.
    sm.update_secret(SecretId=arn, Description="updated after rejected kms change")
    deadline = time.monotonic() + 30.0
    described_desc = None
    while time.monotonic() < deadline:
        described_desc = sm.describe_secret(SecretId=arn).get("Description")
        if described_desc == "updated after rejected kms change":
            break
        time.sleep(2.0)
    assert described_desc == "updated after rejected kms change", (
        f"Description update did not converge in time, last seen: {described_desc!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
