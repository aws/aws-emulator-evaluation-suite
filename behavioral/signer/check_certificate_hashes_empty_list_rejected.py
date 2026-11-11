"""certificate-hashes-empty-list-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-hashes-empty-list-rejected"
GROUP = "overly-permissive"
SERVICES = ["signer"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRevocationStatus rejects an empty certificateHashes list with
    ValidationException, while an otherwise identical request carrying a single
    valid (128-192 hex char) entry (positive control, same file) succeeds."""
    signer = ctx.client("signer")
    common = dict(
        platformId="Notation-OCI-SHA384-ECDSA",
        jobArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-jobs/{'a' * 20}",
        profileVersionArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-profiles/n/{'a' * 10}",
        signatureTimestamp=datetime.now(timezone.utc),
    )

    # Positive control: a non-empty list succeeds.
    resp = signer.get_revocation_status(certificateHashes=["a" * 192], **common)
    assert isinstance(resp.get("revokedEntities"), list), (
        f"positive control (single 192-hex-char hash) did not return a revokedEntities "
        f"list: {resp!r}"
    )

    # Break exactly one thing: an empty list (below the minimum cardinality of 1).
    code, message = _client_error(
        lambda: signer.get_revocation_status(certificateHashes=[], **common)
    )
    assert code == "ValidationException", (
        f"an empty certificateHashes list was rejected with {code!r}, expected "
        f'"ValidationException"'
    )
    expected = "certificateHashes must not be null or empty"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    a target ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects an empty certificateHashes list, but it SUCCEEDED and returned "
        f"{result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
