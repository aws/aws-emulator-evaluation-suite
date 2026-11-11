"""revoke-signature-empty-reason-rejected."""
from __future__ import annotations

import hashlib
import json

from botocore.config import Config

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "revoke-signature-empty-reason-rejected"
GROUP = "overly-permissive"
SERVICES = ["signer"]

NOTATION_PLATFORM = "Notation-OCI-SHA384-ECDSA"
PAYLOAD_FORMAT = "application/vnd.cncf.notary.payload.v1+json"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RevokeSignature rejects an empty reason without revoking; a valid reason then succeeds."""
    signer = ctx.client("signer")
    name = _profile_name(ctx, "revokeempty")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))
    signer.put_signing_profile(profileName=name, platformId=NOTATION_PLATFORM)

    job_id = signer.sign_payload(
        profileName=name,
        payload=_notation_payload("revoke-empty-reason"),
        payloadFormat=PAYLOAD_FORMAT,
    )["jobId"]

    # reason has a modeled minLength of 1, so botocore's own client-side validator would
    # raise ParamValidationError before the request ever left the SDK -- an emulator that
    # happily accepted an empty reason would still grade green. Disable client-side
    # parameter validation so the empty reason actually reaches the service and it is the
    # service's own rejection that gets asserted.
    unvalidated_signer = ctx.client("signer", config=Config(parameter_validation=False))
    code, message = _error(lambda: unvalidated_signer.revoke_signature(jobId=job_id, reason=""))
    assert code == "ValidationException", f"expected ValidationException for an empty reason, got {code!r}"
    expected = "Reason cannot be empty."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the job is not revoked by the failed call.
    job_before = signer.describe_signing_job(jobId=job_id)
    assert not job_before.get("revocationRecord"), (
        f"expected no revocationRecord after a rejected revoke, got {job_before.get('revocationRecord')!r}"
    )

    # Positive control: a valid, non-empty reason revokes the same job.
    signer.revoke_signature(jobId=job_id, reason="valid-reason-for-revocation")
    job_after = signer.describe_signing_job(jobId=job_id)
    assert job_after["revocationRecord"]["reason"] == "valid-reason-for-revocation", (
        f"expected the positive-control reason to stick, got {job_after['revocationRecord'].get('reason')!r}"
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
