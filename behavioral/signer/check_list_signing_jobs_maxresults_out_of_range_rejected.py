"""list-signing-jobs-maxresults-out-of-range-rejected."""
from __future__ import annotations

import hashlib
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-signing-jobs-maxresults-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["signer"]

NOTATION_PLATFORM = "Notation-OCI-SHA384-ECDSA"
PAYLOAD_FORMAT = "application/vnd.cncf.notary.payload.v1+json"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListSigningJobs rejects a maxResults above the modeled range (25); in range, it truncates a real page."""
    signer = ctx.client("signer")
    name = _profile_name(ctx, "maxresults")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))

    signer.put_signing_profile(
        profileName=name, platformId=NOTATION_PLATFORM, tags={"sim2real": CHECK}
    )
    job_ids = {
        signer.sign_payload(
            profileName=name, payload=_notation_payload(salt), payloadFormat=PAYLOAD_FORMAT
        )["jobId"]
        for salt in ("first", "second")
    }

    def probe():
        return _visible_count(signer, job_ids)

    visible = _poll_until(probe, lambda n: n >= 2, timeout_s=60.0, interval_s=5.0)
    assert visible >= 2, f"expected both signing jobs visible via ListSigningJobs, saw {visible}"

    # maxResults=0 is rejected by botocore's own client-side range validation before any
    # request is sent (ParamValidationError), so it is not a real-AWS observation and is
    # deliberately not asserted here.
    above_range, message = _error(lambda: signer.list_signing_jobs(maxResults=26))
    assert above_range == "ValidationException", (
        f"expected ValidationException for maxResults=26, got {above_range!r}"
    )
    expected = "MaxResults parameter must be an integer between 1 and 25"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: with >=2 real signing jobs present, an in-range maxResults=1
    # truncates the page to exactly 1 and signals more results remain.
    resp = signer.list_signing_jobs(maxResults=1)
    jobs = resp.get("jobs", [])
    assert len(jobs) == 1, f"expected exactly 1 job with maxResults=1, got {len(jobs)}"
    assert resp.get("nextToken"), "expected nextToken when more results remain beyond maxResults=1"


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


def _visible_count(signer, job_ids: set) -> int:
    seen = set()
    next_token = None
    for _ in range(20):
        kwargs = {"maxResults": 25}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = signer.list_signing_jobs(**kwargs)
        seen.update(job["jobId"] for job in resp.get("jobs", []) if job["jobId"] in job_ids)
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return len(seen)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


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
