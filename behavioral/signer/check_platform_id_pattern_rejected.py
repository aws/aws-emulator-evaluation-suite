"""platform-id-pattern-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "platform-id-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["signer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRevocationStatus rejects a platformId that violates ^[a-zA-Z0-9_-]+$ with
    ValidationException, while an otherwise identical request with a valid platformId
    succeeds (positive control in the same file)."""
    signer = ctx.client("signer")
    common = dict(
        jobArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-jobs/{'a' * 20}",
        profileVersionArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-profiles/n/{'a' * 10}",
        certificateHashes=["a" * 192],
        signatureTimestamp=datetime.now(timezone.utc),
    )

    # Positive control: a syntactically valid, real platform id succeeds.
    resp = signer.get_revocation_status(platformId="Notation-OCI-SHA384-ECDSA", **common)
    assert resp["revokedEntities"] == [], f"expected no revoked entities, got {resp['revokedEntities']!r}"

    # Break exactly one thing: platformId contains characters outside the allowed set.
    bad_platform = "bad platform!"
    code, message = _client_error(
        lambda: signer.get_revocation_status(platformId=bad_platform, **common)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        f"1 validation error detected: Value '{bad_platform}' at 'platformId' failed to satisfy "
        f"constraint: Member must satisfy regular expression pattern: ^[a-zA-Z0-9_-]+$"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
