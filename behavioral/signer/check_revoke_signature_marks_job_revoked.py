"""revoke-signature-marks-job-revoked."""
from __future__ import annotations

import hashlib
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "revoke-signature-marks-job-revoked"
GROUP = "state"
SERVICES = ["signer"]

NOTATION_PLATFORM = "Notation-OCI-SHA384-ECDSA"
PAYLOAD_FORMAT = "application/vnd.cncf.notary.payload.v1+json"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RevokeSignature marks a completed signing job's signature as revoked with a record
    naming the reason, the time and the revoking identity, without moving the job off its
    terminal status."""
    signer = ctx.client("signer")
    sts = ctx.client("sts")
    name = _profile_name(ctx, "revokesig")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))

    signer.put_signing_profile(
        profileName=name, platformId=NOTATION_PLATFORM, tags={"sim2real-check": CHECK}
    )
    job_id = signer.sign_payload(
        profileName=name,
        payload=_notation_payload("revoke-target"),
        payloadFormat=PAYLOAD_FORMAT,
    )["jobId"]

    job_before = signer.describe_signing_job(jobId=job_id)
    assert not job_before.get("revocationRecord"), (
        f"expected no revocationRecord before RevokeSignature, got "
        f"{job_before.get('revocationRecord')!r}"
    )

    reason = "sim2real-behavioral-fidelity-check"
    signer.revoke_signature(jobId=job_id, reason=reason)
    caller_arn = sts.get_caller_identity()["Arn"]

    def probe():
        return signer.describe_signing_job(jobId=job_id)

    job = _poll_until(
        probe,
        lambda j: bool(j.get("revocationRecord")),
        timeout_s=30.0,
        interval_s=2.0,
    )
    record = job["revocationRecord"]
    assert record["reason"] == reason, (
        f"expected revocationRecord.reason={reason!r}, got {record.get('reason')!r}"
    )
    assert record["revokedAt"] is not None, "expected revocationRecord.revokedAt to be set, got None"
    assert record["revokedBy"] == caller_arn, (
        f"expected revocationRecord.revokedBy={caller_arn!r} (the calling identity), "
        f"got {record.get('revokedBy')!r}"
    )
    assert job["status"] == "Succeeded", (
        f"expected job status to remain Succeeded after revocation, got {job['status']!r}"
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
