"""terminate-service-job-unknown-id-is-accepted."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "terminate-service-job-unknown-id-is-accepted"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TerminateServiceJob on an unknown job id is accepted idempotently, mirroring TerminateJob."""
    batch = ctx.client("batch")
    bogus_job_id = str(uuid.uuid4())

    # This must NOT raise -- TerminateServiceJob accepts a nonexistent job id
    # the same way TerminateJob does for regular jobs, rather than rejecting it.
    resp = batch.terminate_service_job(jobId=bogus_job_id, reason="sim2real-behavioral-unknown-id")
    # TerminateServiceJobResponse declares no output members: a real "accepted"
    # response body carries nothing but the transport envelope, never an error
    # payload -- assert the body itself is that empty success shape.
    body = {k: v for k, v in resp.items() if k != "ResponseMetadata"}
    assert body == {}, f"expected empty TerminateServiceJobResponse body, got {body!r}"

    # Calling it again with the same unknown id must also succeed (still accepted,
    # not just accepted-once).
    resp2 = batch.terminate_service_job(jobId=bogus_job_id, reason="sim2real-behavioral-unknown-id-again")
    body2 = {k: v for k, v in resp2.items() if k != "ResponseMetadata"}
    assert body2 == {}, f"expected repeat TerminateServiceJob on the same unknown id to stay accepted with an empty body, got {body2!r}"

    # Resulting state: "accepted" must not mean "materialized" -- terminating an
    # unknown id must not have conjured a job record into existence.
    error = _error(lambda: batch.describe_service_job(jobId=bogus_job_id))
    code, message = error.get("Code"), error.get("Message")
    assert code == "ClientException", f"expected DescribeServiceJob on the never-materialized id to raise ClientException, got code={code!r}"
    assert message == _describe_unknown_message(ctx, bogus_job_id), (
        f"expected the exact DescribeServiceJob unknown-id message, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
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
