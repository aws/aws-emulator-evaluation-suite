"""list-signing-jobs-reflects-recent-signing-activity."""
from __future__ import annotations

import hashlib
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-signing-jobs-reflects-recent-signing-activity"
GROUP = "data-plane"
SERVICES = ["signer"]

NOTATION_PLATFORM = "Notation-OCI-SHA384-ECDSA"
PAYLOAD_FORMAT = "application/vnd.cncf.notary.payload.v1+json"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A completed SignPayload job becomes visible through ListSigningJobs status filtering."""
    signer = ctx.client("signer")
    name = _profile_name(ctx, "listjobs")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))

    signer.put_signing_profile(
        profileName=name,
        platformId=NOTATION_PLATFORM,
        tags={"sim2real-env": "behavioral"},
    )
    job_id = signer.sign_payload(
        profileName=name,
        payload=_notation_payload("list-target"),
        payloadFormat=PAYLOAD_FORMAT,
    )["jobId"]

    account_id = ctx.client("sts").get_caller_identity()["Account"]

    def probe():
        return _job_present(signer, job_id, status="Succeeded", job_invoker=account_id)

    found = _poll_until(probe, lambda found: found, timeout_s=60.0, interval_s=5.0)
    assert found, (
        f"job {job_id} never appeared via ListSigningJobs(status=Succeeded, "
        f"jobInvoker={account_id}) within 60s"
    )

    # The job is now confirmed Succeeded; a status filter that mattered would exclude it
    # from every other terminal status, and a jobInvoker filter that mattered would
    # exclude it from a mismatched invoker. Both are structural, not timing-dependent.
    wrong_status = _job_present(signer, job_id, status="Failed", job_invoker=account_id)
    assert not wrong_status, (
        f"job {job_id} is Succeeded but ListSigningJobs(status=Failed) still returned it; "
        "the status filter is not being applied"
    )

    wrong_invoker = _job_present(
        signer, job_id, status="Succeeded", job_invoker="111122223333"
    )
    assert not wrong_invoker, (
        f"job {job_id} was invoked by {account_id} but ListSigningJobs(jobInvoker="
        "111122223333) still returned it; the jobInvoker filter is not being applied"
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


def _job_present(signer, job_id: str, *, status: str, job_invoker: str) -> bool:
    next_token = None
    for _ in range(20):
        kwargs = {"status": status, "jobInvoker": job_invoker, "maxResults": 25}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = signer.list_signing_jobs(**kwargs)
        if any(job["jobId"] == job_id for job in resp.get("jobs", [])):
            return True
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return False


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
