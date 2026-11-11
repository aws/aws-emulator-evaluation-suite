"""job-arn-too-long-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-arn-too-long-rejected"
GROUP = "overly-permissive"
SERVICES = ["signer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRevocationStatus accepts a syntactically valid jobArn of exactly 2048 chars and rejects one of 2049
    chars with ValidationException and the exact length message.
    """
    signer = ctx.client("signer")
    common = dict(
        platformId="Notation-OCI-SHA384-ECDSA",
        profileVersionArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-profiles/n/{'a' * 10}",
        certificateHashes=["a" * 192],
        signatureTimestamp=datetime.now(timezone.utc),
    )

    prefix = f"arn:aws:signer:{ctx.region}:111122223333:/signing-jobs/"

    # Positive control: exactly the maximum allowed length (2048) succeeds.
    max_job_arn = prefix + "j" * (2048 - len(prefix))
    assert len(max_job_arn) == 2048, f"test construction bug: built {len(max_job_arn)}-char jobArn, want 2048"
    resp = signer.get_revocation_status(jobArn=max_job_arn, **common)
    assert isinstance(resp.get("revokedEntities"), list), (
        f"positive control: expected a revokedEntities list back for a 2048-char jobArn, got {resp!r}"
    )

    # Break exactly one thing: one character over the maximum.
    over_job_arn = prefix + "j" * (2049 - len(prefix))
    assert len(over_job_arn) == 2049, f"test construction bug: built {len(over_job_arn)}-char jobArn, want 2049"
    code, message = _client_error(
        lambda: signer.get_revocation_status(jobArn=over_job_arn, **common)
    )
    assert code == "ValidationException", f"expected ValidationException for a 2049-char jobArn, got {code!r}"
    expected = (
        f"1 validation error detected: Value '{over_job_arn}' at 'jobArn' failed to satisfy "
        f"constraint: Member must have length less than or equal to 2048"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects a 2049-char jobArn, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
