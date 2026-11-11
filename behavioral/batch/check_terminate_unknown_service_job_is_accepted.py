"""terminate-unknown-service-job-is-accepted."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "terminate-unknown-service-job-is-accepted"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TerminateServiceJob on an unknown job ID is accepted without error, mirroring TerminateJob's
    fire-and-forget contract for a distinct API, and does not fabricate a job as a side effect."""
    batch = ctx.client("batch")
    fake_job_id = str(uuid.uuid4())

    # Must not raise -- TerminateServiceJob accepts unknown job IDs silently (fire-and-forget).
    resp = batch.terminate_service_job(jobId=fake_job_id, reason="sim2real-behav-terminate-unknown")
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected 200 accepting an unknown service job id, got {status}"
    # TerminateServiceJobResponse declares zero output members -- the accepted
    # response body must carry nothing but the transport envelope.
    body = {k: v for k, v in resp.items() if k != "ResponseMetadata"}
    assert body == {}, f"expected an empty TerminateServiceJobResponse body, got {body!r}"

    # Calling it again on the same still-unknown ID must also be accepted (idempotent no-op).
    resp2 = batch.terminate_service_job(jobId=fake_job_id, reason="sim2real-behav-terminate-unknown-again")
    status2 = resp2["ResponseMetadata"]["HTTPStatusCode"]
    assert status2 == 200, f"expected 200 on the repeated terminate of an unknown service job id, got {status2}"
    body2 = {k: v for k, v in resp2.items() if k != "ResponseMetadata"}
    assert body2 == {}, f"expected an empty TerminateServiceJobResponse body on the repeat call, got {body2!r}"

    # The accepted terminate call must not have fabricated a describable job record.
    error = _error(lambda: batch.describe_service_job(jobId=fake_job_id))
    describe_code, message = error.get("Code"), error.get("Message")
    assert describe_code == "ClientException", (
        f"TerminateServiceJob on an unknown id created a describable job: {describe_code!r}"
    )
    assert message == _describe_unknown_message(ctx, fake_job_id), (
        f"expected the exact DescribeServiceJob unknown-id message, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _describe_unknown_message(ctx, job_id):
    """The exact message DescribeServiceJob returns for a service job id that does not exist."""
    return f"arn:aws:batch:{ctx.region}:{ctx.account}:service-job/{job_id} does not exist"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
