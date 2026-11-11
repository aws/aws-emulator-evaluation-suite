"""multiple-certificate-hashes-batch."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multiple-certificate-hashes-batch"
GROUP = "read-semantics"
SERVICES = ["signer"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRevocationStatus accepts 5 valid certificateHashes with empty revokedEntities, rejects a batch whose
    5th entry is one char short with ValidationException and the exact message, and rejects a 6th entry with
    the exact cardinality-cap message.
    """
    signer = ctx.client("signer")
    common = dict(
        platformId="Notation-OCI-SHA384-ECDSA",
        jobArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-jobs/{'h' * 20}",
        profileVersionArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-profiles/n/{'h' * 10}",
        signatureTimestamp=datetime.now(timezone.utc),
    )

    five_hashes = [f"{i:x}" * 192 for i in range(5)]
    resp = signer.get_revocation_status(certificateHashes=five_hashes, **common)
    assert resp["revokedEntities"] == [], f"expected no revoked entities, got {resp['revokedEntities']!r}"

    # Break exactly one thing: the 5th (last) entry drops one char under the 128-char floor
    # while positions 1-4 stay well-formed, so validating only the first entry would accept it.
    malformed = "g" * 127
    tail_malformed = five_hashes[:4] + [malformed]
    code, message = _client_error(
        lambda: signer.get_revocation_status(certificateHashes=tail_malformed, **common)
    )
    assert code == "ValidationException", f"expected ValidationException for a malformed 5th entry, got {code!r}"
    expected = f"Certificate hash {malformed} must be hexadecimal and between 128 and 256 bits long"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Break exactly one thing: a 6th hash, one over the real 5-entry cap.
    six_hashes = five_hashes + ["f" * 192]
    code, message = _client_error(
        lambda: signer.get_revocation_status(certificateHashes=six_hashes, **common)
    )
    assert code == "ValidationException", f"expected ValidationException for a 6th entry over cap, got {code!r}"
    expected = "certificateHashes must not contain more than 5 hashes"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises, so a target that
    accepts a batch real AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this batch, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
