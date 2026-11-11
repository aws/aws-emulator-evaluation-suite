"""describe-signing-job-unknown-job-not-found."""
from __future__ import annotations

import hashlib
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-signing-job-unknown-job-not-found"
GROUP = "error-semantics"
SERVICES = ["signer"]

NOTATION_PLATFORM = "Notation-OCI-SHA384-ECDSA"
PAYLOAD_FORMAT = "application/vnd.cncf.notary.payload.v1+json"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeSigningJob raises ResourceNotFoundException for a jobId that was never created."""
    signer = ctx.client("signer")

    bogus_job_id = "00000000-0000-0000-0000-000000000000"
    code, message = _error(lambda: signer.describe_signing_job(jobId=bogus_job_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Signing job not found for id {bogus_job_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a real jobId describes successfully and reaches a terminal state.
    name = _profile_name(ctx, "describeok")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))
    signer.put_signing_profile(
        profileName=name, platformId=NOTATION_PLATFORM, tags={"sim2real-env": "behavioral"}
    )
    job_id = signer.sign_payload(
        profileName=name,
        payload=_notation_payload("describe-control"),
        payloadFormat=PAYLOAD_FORMAT,
    )["jobId"]

    def probe():
        return signer.describe_signing_job(jobId=job_id)

    described = _poll_until(probe, lambda j: j["status"] != "InProgress", timeout_s=30.0)
    assert described["jobId"] == job_id, f"expected jobId {job_id!r}, got {described['jobId']!r}"
    assert described["status"] == "Succeeded", f"expected Succeeded, got {described['status']!r}"


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

def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0):
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
