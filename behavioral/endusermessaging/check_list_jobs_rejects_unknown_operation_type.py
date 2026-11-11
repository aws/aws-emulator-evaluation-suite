"""list-jobs-rejects-unknown-operation-type."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-jobs-rejects-unknown-operation-type"
GROUP = "jobs"
SERVICES = ["endusermessaging"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListJobs refuses an operationType outside the four asynchronous operations with
    ValidationException listing them; filtered by a fresh profile it answers no jobs.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-jobs-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    code, message = _error(lambda: eum.list_jobs(operationType="CreateBrandProfile"))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == (
        "Invalid value for 'operationType': unknown operation type: CreateBrandProfile. Valid values: "
        "CreateRegistrationsFromBrandProfile | UpdateRegistrationsFromBrandProfile | "
        "CreateBrandProfileFromRegistration | UpdateBrandProfileFromRegistration"
    ), f"unexpected message {message!r}"

    jobs = eum.list_jobs(brandProfileId=bpid, operationType="CreateRegistrationsFromBrandProfile")["jobs"]
    assert jobs == [], f"a profile that ran no job must list none, got {len(jobs)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
