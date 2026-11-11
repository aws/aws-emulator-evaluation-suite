"""signature-timestamp-future-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signature-timestamp-future-rejected"
GROUP = "overly-permissive"
SERVICES = ["signer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRevocationStatus accepts a signatureTimestamp decades in the past and rejects one decades in the
    future with ValidationException and the exact must-be-earlier message.
    """
    signer = ctx.client("signer")
    common = dict(
        platformId="Notation-OCI-SHA384-ECDSA",
        jobArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-jobs/{'c' * 20}",
        profileVersionArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-profiles/n/{'c' * 10}",
        certificateHashes=["c" * 192],
    )

    far_past = datetime(1980, 1, 2, tzinfo=timezone.utc)
    far_future = datetime(2066, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    # Positive control: a timestamp decades in the past is accepted.
    past_resp = signer.get_revocation_status(signatureTimestamp=far_past, **common)
    assert past_resp["revokedEntities"] == [], (
        f"expected no revoked entities for a valid far-past signatureTimestamp; "
        f"got {past_resp['revokedEntities']!r}"
    )

    # Break exactly one thing: a timestamp decades in the future.
    code, message = _client_error(
        lambda: signer.get_revocation_status(signatureTimestamp=far_future, **common)
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a signatureTimestamp decades in the future; "
        f"got {code!r}"
    )
    expected = "Invalid signatureTimestamp: 2066-01-02T03:04:05Z must be earlier than present time"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its ClientError code and message; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded with {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
