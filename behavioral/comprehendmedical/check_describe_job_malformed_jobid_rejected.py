"""describe-job-malformed-jobid-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-job-malformed-jobid-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehendmedical"]


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribePHIDetectionJob rejects a JobId that violates the id's charset/length constraint."""
    cm = ctx.client("comprehendmedical")

    # JobId must match ^([\p{L}\p{Z}\p{N}_.:/=+\-%@]*)$ with length 1-32; "#" and "!" are
    # disallowed characters, so this is a malformed id, not merely an absent one.
    bad_job_id = "not#a#valid#job#id!"
    code, message = _error(lambda: cm.describe_phi_detection_job(JobId=bad_job_id))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected = r"1 validation error detected: Value at 'jobId' failed to satisfy constraint: Member must satisfy regular expression pattern: ^([\p{L}\p{Z}\p{N}_.:/=+\-%@]*)$"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a syntactically valid (but nonexistent) JobId reaches the lookup logic
    # and is rejected for a different, specific reason -- proving the service actually validates
    # syntax before existence rather than rejecting every describe call unconditionally.
    valid_but_absent_job_id = "a" * 32
    code2, message2 = _error(lambda: cm.describe_phi_detection_job(JobId=valid_but_absent_job_id))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected2 = "Could not find specified job."
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
