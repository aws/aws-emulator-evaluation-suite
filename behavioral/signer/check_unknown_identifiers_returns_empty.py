"""unknown-identifiers-returns-empty."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "unknown-identifiers-returns-empty"
GROUP = "read-semantics"
SERVICES = ["signer"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRevocationStatus with well-formed but fabricated jobArn, profileVersionArn and certificateHashes
    succeeds with an empty revokedEntities list rather than a not-found error.
    """
    signer = ctx.client("signer")
    fabricated_job_arn = f"arn:aws:signer:{ctx.region}:111122223333:/signing-jobs/{'a' * 20}"
    fabricated_profile_arn = (
        f"arn:aws:signer:{ctx.region}:111122223333:/signing-profiles/nope/{'a' * 10}"
    )
    fabricated_hash = "f" * 192

    resp = signer.get_revocation_status(
        platformId="Notation-OCI-SHA384-ECDSA",
        jobArn=fabricated_job_arn,
        profileVersionArn=fabricated_profile_arn,
        certificateHashes=[fabricated_hash],
        signatureTimestamp=datetime.now(timezone.utc),
    )

    assert resp["revokedEntities"] == [], (
        f"expected empty revokedEntities for fabricated jobArn/profileVersionArn/hash, "
        f"got {resp['revokedEntities']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
