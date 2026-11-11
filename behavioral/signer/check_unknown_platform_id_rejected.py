"""unknown-platform-id-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unknown-platform-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["signer"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRevocationStatus succeeds for a registered platformId and rejects a syntactically valid but
    unregistered one with ValidationException and the exact message, so platformId is checked against known
    platforms.
    """
    signer = ctx.client("signer")
    common = dict(
        jobArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-jobs/{'i' * 20}",
        profileVersionArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-profiles/n/{'i' * 10}",
        certificateHashes=["a" * 192],
        signatureTimestamp=datetime.now(timezone.utc),
    )

    # Positive control: a real, registered platform id succeeds.
    resp = signer.get_revocation_status(platformId="Notation-OCI-SHA384-ECDSA", **common)
    assert resp["revokedEntities"] == [], f"expected no revoked entities, got {resp['revokedEntities']!r}"

    # Break exactly one thing: a syntactically valid but unregistered platformId.
    bad_platform = "MyMadeUpPlatform-123_x"
    code, message = _client_error(
        lambda: signer.get_revocation_status(platformId=bad_platform, **common)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = f"Invalid platformId: {bad_platform}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this platformId, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
