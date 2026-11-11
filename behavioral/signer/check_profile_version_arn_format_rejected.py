"""profile-version-arn-format-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "profile-version-arn-format-rejected"
GROUP = "overly-permissive"
SERVICES = ["signer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRevocationStatus accepts a syntactically valid but non-existent profileVersionArn and rejects a same-
    length non-ARN string with ValidationException and the exact message, so it validates ARN shape, not just
    length.
    """
    signer = ctx.client("signer")
    common = dict(
        platformId="Notation-OCI-SHA384-ECDSA",
        jobArn=f"arn:aws:signer:{ctx.region}:111122223333:/signing-jobs/{'a' * 20}",
        certificateHashes=["a" * 192],
        signatureTimestamp=datetime.now(timezone.utc),
    )

    valid_profile_arn = f"arn:aws:signer:{ctx.region}:111122223333:/signing-profiles/n/{'a' * 10}"

    # Positive control: a syntactically valid (if non-existent) ARN succeeds.
    resp = signer.get_revocation_status(profileVersionArn=valid_profile_arn, **common)
    revoked = resp.get("revokedEntities")
    assert isinstance(revoked, list), f"expected a list of revokedEntities, got {revoked!r}"

    # Break exactly one thing: same length, but not ARN-shaped at all.
    malformed = "a" * len(valid_profile_arn)
    code, message = _client_error(
        lambda: signer.get_revocation_status(profileVersionArn=malformed, **common)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = f"Invalid profileVersionArn: {malformed}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this profileVersionArn, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
