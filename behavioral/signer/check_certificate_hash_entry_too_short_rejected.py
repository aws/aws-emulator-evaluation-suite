"""certificate-hash-entry-too-short-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-hash-entry-too-short-rejected"
GROUP = "overly-permissive"
SERVICES = ["signer"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRevocationStatus accepts a 128-hex-char certificateHashes entry and reports it unrevoked, and rejects
    a 127-char entry with ValidationException and the exact length message.
    """
    signer = ctx.client("signer")
    common = dict(
        platformId="Notation-OCI-SHA384-ECDSA",
        jobArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-jobs/{'a' * 20}",
        profileVersionArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-profiles/n/{'a' * 10}",
        signatureTimestamp=datetime.now(timezone.utc),
    )

    # Positive control: a 128-hex-char hash entry (the real minimum) succeeds,
    # and the non-revoked entry is not reported back as revoked.
    resp = signer.get_revocation_status(certificateHashes=["a" * 128], **common)
    assert resp.get("revokedEntities") == [], (
        f"expected revokedEntities == [] for a valid 128-char hash, got {resp.get('revokedEntities')!r}"
    )

    # Break exactly one thing: a 127-hex-char entry, one below the minimum.
    short_hash = "a" * 127
    code, message = _client_error(
        lambda: signer.get_revocation_status(certificateHashes=[short_hash], **common)
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a 127-char (one-below-minimum) hash entry, got {code!r}"
    )
    expected = f"Certificate hash {short_hash} must be hexadecimal and between 128 and 256 bits long"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING an entry real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
