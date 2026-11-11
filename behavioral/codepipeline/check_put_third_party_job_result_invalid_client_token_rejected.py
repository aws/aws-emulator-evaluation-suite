"""put-third-party-job-result-invalid-client-token-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-third-party-job-result-invalid-client-token-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutThirdPartyJobSuccessResult and PutThirdPartyJobFailureResult with a wrong clientToken fail with
    JobNotFoundException and its exact message for an arbitrary and a well-formed nonexistent jobId, never
    InvalidClientTokenException.
    """
    cp = ctx.client("codepipeline")

    arbitrary_job_id = "not-a-real-job-id"
    err_arbitrary = _error(
        lambda: cp.put_third_party_job_success_result(
            jobId=arbitrary_job_id, clientToken="bogus-client-token"
        )
    )
    assert err_arbitrary.get("Code") == "JobNotFoundException", (
        f"expected JobNotFoundException for a non-UUID jobId, got {err_arbitrary!r}"
    )
    expected_message = f"Job with id '{arbitrary_job_id}' does not exist."
    assert err_arbitrary.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err_arbitrary.get('Message')!r}"
    )

    unknown_job_id = str(uuid.uuid4())  # well-formed UUID, but no such job was ever dispatched

    err_not_found_success = _error(
        lambda: cp.put_third_party_job_success_result(
            jobId=unknown_job_id, clientToken="bogus-client-token"
        )
    )
    assert err_not_found_success.get("Code") == "JobNotFoundException", (
        f"expected JobNotFoundException from PutThirdPartyJobSuccessResult on an unknown "
        f"jobId, got {err_not_found_success!r}"
    )
    expected_message = f"Job with id '{unknown_job_id}' does not exist."
    assert err_not_found_success.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err_not_found_success.get('Message')!r}"
    )

    err_not_found_failure = _error(
        lambda: cp.put_third_party_job_failure_result(
            jobId=unknown_job_id,
            clientToken="bogus-client-token",
            failureDetails={"type": "JobFailed", "message": "probe"},
        )
    )
    assert err_not_found_failure.get("Code") == "JobNotFoundException", (
        f"expected JobNotFoundException from PutThirdPartyJobFailureResult on an unknown "
        f"jobId, got {err_not_found_failure!r}"
    )
    expected_message = f"Job with id '{unknown_job_id}' does not exist."
    assert err_not_found_failure.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err_not_found_failure.get('Message')!r}"
    )

    # job-existence is checked before client-token validity on both operations: a bad token on
    # a nonexistent job must surface as "no such job", not as "wrong token"
    assert err_arbitrary.get("Code") != "InvalidClientTokenException", (
        f"job-existence check must precede client-token validation, got {err_arbitrary!r}"
    )
    assert err_not_found_success.get("Code") != "InvalidClientTokenException", (
        f"job-existence check must precede client-token validation, got {err_not_found_success!r}"
    )
    assert err_not_found_failure.get("Code") != "InvalidClientTokenException", (
        f"job-existence check must precede client-token validation, got {err_not_found_failure!r}"
    )


def _error(fn) -> dict:
    """Call fn and return the botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
