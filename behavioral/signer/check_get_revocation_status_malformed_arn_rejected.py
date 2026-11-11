"""get-revocation-status-malformed-arn-rejected."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-revocation-status-malformed-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["signer"]

NOTATION_PLATFORM = "Notation-OCI-SHA384-ECDSA"
PAYLOAD_FORMAT = "application/vnd.cncf.notary.payload.v1+json"
# Two concatenated SHA384 (48-byte) hex digests, the shape GetRevocationStatus validates server-side.
# A short hash such as "deadbeef" is itself rejected with ValidationException, which would confound
# the ARN check below, so every call uses this correctly shaped (not cryptographically real) hash.
SHAPED_CERTIFICATE_HASH = "ab" * 96
MALFORMED_ARN = "arn:aws:signer:us-east-1:123456789012:not-a-real-arn-shape"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRevocationStatus rejects a malformed profileVersionArn/jobArn with ValidationException and the exact
    message, while the same call with a real profile version and job ARN succeeds with empty revokedEntities,
    so the rejection is about ARN validity.
    """
    signer = ctx.client("signer")
    account = ctx.account

    # The rejected call uses the same platform as the positive control: GetRevocationStatus
    # refuses the Lambda platform outright, which would mask the ARN decision under test.
    code, message = _error(
        lambda: signer.get_revocation_status(
            signatureTimestamp=datetime.now(timezone.utc),
            platformId=NOTATION_PLATFORM,
            profileVersionArn=MALFORMED_ARN,
            jobArn=MALFORMED_ARN,
            certificateHashes=[SHAPED_CERTIFICATE_HASH],
        )
    )
    assert code == "ValidationException", (
        f"malformed profileVersionArn/jobArn: expected ValidationException, got {code!r}"
    )
    expected = f"Invalid profileVersionArn: {MALFORMED_ARN}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a real profileVersionArn and a real jobArn, everything else identical.
    name = _profile_name(ctx, "revstatus")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))
    profile = signer.put_signing_profile(
        profileName=name, platformId=NOTATION_PLATFORM, tags={"sim2real-env": "behavioral"}
    )
    job_id = signer.sign_payload(
        profileName=name,
        payload=_notation_payload("revstatus-control"),
        payloadFormat=PAYLOAD_FORMAT,
    )["jobId"]
    real_job_arn = f"arn:aws:signer:{ctx.region}:{account}:/signing-jobs/{job_id}"

    live = signer.get_revocation_status(
        signatureTimestamp=datetime.now(timezone.utc),
        platformId=NOTATION_PLATFORM,
        profileVersionArn=profile["profileVersionArn"],
        jobArn=real_job_arn,
        certificateHashes=[SHAPED_CERTIFICATE_HASH],
    )
    assert live["revokedEntities"] == [], (
        f"real ARNs with nothing revoked must report an empty revokedEntities, got "
        f"{live['revokedEntities']!r}"
    )


def _profile_name(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-signer-{kind}-").replace("-", "_")


def _cancel_quietly(signer, profile_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        signer.cancel_signing_profile(profileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _notation_payload(salt: str) -> bytes:
    digest = hashlib.sha256(f"sim2real-signer-payload-{salt}".encode("utf-8")).hexdigest()
    body = {
        "targetArtifact": {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "digest": f"sha256:{digest}",
            "size": 1024,
            "annotations": {"sim2real.check": "true"},
        }
    }
    return json.dumps(body).encode("utf-8")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so an
    emulator that accepts what AWS refuses reads as an acceptance, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
