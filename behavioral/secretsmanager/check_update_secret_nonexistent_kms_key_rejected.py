"""update-secret-nonexistent-kms-key-rejected."""
from __future__ import annotations

import re as _re

import time
import uuid

from behavioral_harness import tags

CHECK = "update-secret-nonexistent-kms-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateSecret with a well-formed but nonexistent KmsKeyId ARN is rejected with
    InvalidParameterException rather than being silently stored, leaving the secret's
    KmsKeyId unchanged; an unrelated UpdateSecret call on the same secret still succeeds."""
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-sm-")
    created = sm.create_secret(
        Name=name, SecretString="value", Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    before = sm.describe_secret(SecretId=arn)
    kms_key_id_before = before.get("KmsKeyId")

    bogus_key_arn = f"arn:aws:kms:{ctx.region}:{account_id}:key/{uuid.uuid4()}"
    code, message = _error_code(lambda: sm.update_secret(SecretId=arn, KmsKeyId=bogus_key_arn))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    # message varies: it embeds the downstream KMS call's per-request Request ID; the rest is exact.
    assert _re.fullmatch(_kms_refusal_pattern(bogus_key_arn), message or ""), (
        f"unexpected invalid-KMS-key message: {message!r}"
    )

    # Effect absent: KmsKeyId on the secret is unchanged after the rejected call.
    after_rejected = sm.describe_secret(SecretId=arn)
    assert after_rejected.get("KmsKeyId") == kms_key_id_before, (
        f"KmsKeyId changed after a rejected UpdateSecret: "
        f"before={kms_key_id_before!r} after={after_rejected.get('KmsKeyId')!r}"
    )

    # Positive control: a valid UpdateSecret call (no bogus KmsKeyId) still succeeds.
    sm.update_secret(SecretId=arn, Description="updated-by-check")
    deadline = time.monotonic() + 30.0
    described_desc = None
    while time.monotonic() < deadline:
        described_desc = sm.describe_secret(SecretId=arn).get("Description")
        if described_desc == "updated-by-check":
            break
        time.sleep(2.0)
    assert described_desc == "updated-by-check", (
        f"positive-control Description update did not converge in time, last seen: {described_desc!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
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
