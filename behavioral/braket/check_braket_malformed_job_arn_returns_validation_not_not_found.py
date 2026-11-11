"""braket-malformed-job-arn-returns-validation-not-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "braket-malformed-job-arn-returns-validation-not-not-found"
GROUP = "error-semantics"
SERVICES = ["braket"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetJob on a malformed jobArn in the caller's account fails with ValidationException "jobArn parameter is
    not valid.", while a well-formed but nonexistent jobArn fails with ResourceNotFoundException
    "Job <account>#<name> not found"."""
    braket = ctx.client("braket")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    ghost_name = ctx.unique_name("sim2real-ghost-")
    well_formed_but_nonexistent = f"arn:aws:braket:{ctx.region}:{account_id}:job/{ghost_name}"
    control = _client_error(lambda: braket.get_job(jobArn=well_formed_but_nonexistent))
    assert control["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but nonexistent jobArn, "
        f"got {control!r}"
    )
    expected = f"Job {account_id}#{ghost_name} not found"
    assert control["Message"] == expected, f"expected message {expected!r}, got {control['Message']!r}"

    malformed = f"arn:aws:braket:{ctx.region}:{account_id}:not-a-job-resource"
    err = _client_error(lambda: braket.get_job(jobArn=malformed))
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err!r}"
    assert err["Message"] == "jobArn parameter is not valid.", (
        f"expected message 'jobArn parameter is not valid.', got {err['Message']!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
