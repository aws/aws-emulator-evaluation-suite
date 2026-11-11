"""certificate-hash-length-boundaries-accepted."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-hash-length-boundaries-accepted"
GROUP = "read-semantics"
SERVICES = ["signer"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRevocationStatus accepts certificateHashes entries of 128 and 256 hex chars (empty revokedEntities)
    and rejects a 257-char entry with ValidationException and the exact length message, so the 256-char
    ceiling is real.
    """
    signer = ctx.client("signer")
    common = dict(
        platformId="Notation-OCI-SHA384-ECDSA",
        jobArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-jobs/{'j' * 20}",
        profileVersionArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-profiles/n/{'j' * 10}",
        signatureTimestamp=datetime.now(timezone.utc),
    )

    min_resp = signer.get_revocation_status(certificateHashes=["a" * 128], **common)
    max_resp = signer.get_revocation_status(certificateHashes=["a" * 256], **common)

    assert min_resp["revokedEntities"] == [], (
        f"expected empty revokedEntities for the 128-char minimum, got {min_resp['revokedEntities']!r}"
    )
    assert max_resp["revokedEntities"] == [], (
        f"expected empty revokedEntities for the 256-char maximum, got {max_resp['revokedEntities']!r}"
    )

    long_hash = "a" * 257
    code, message = _client_error(
        lambda: signer.get_revocation_status(certificateHashes=[long_hash], **common)
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a 257-char entry (one past the maximum), got {code!r}"
    )
    expected = f"Certificate hash {long_hash} must be hexadecimal and between 128 and 256 bits long"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its ClientError code and message; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected ClientError for a 257-char certificateHashes entry, call succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
