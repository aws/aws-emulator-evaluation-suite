"""op-contract-update-workgroup-nonexistent-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-update-workgroup-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateWorkGroup on a WorkGroup name that does not exist is rejected with
    InvalidRequestException and mutates nothing; the same call shape succeeds
    (positive control) against a real workgroup."""
    athena = ctx.client("athena")

    missing_name = ctx.unique_name("sim2real-behav-wg-missing-")
    code, message = _error(
        lambda: athena.update_work_group(
            WorkGroup=missing_name,
            Description="should not apply",
            ConfigurationUpdates={"EnforceWorkGroupConfiguration": True},
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "WorkGroup is not found.", message

    # The workgroup truly does not exist: GetWorkGroup on the same name is rejected too.
    get_code, get_message = _error(lambda: athena.get_work_group(WorkGroup=missing_name))
    assert get_code == "InvalidRequestException", get_code
    assert get_message == "WorkGroup is not found.", get_message

    # Positive control: an identical UpdateWorkGroup call against a workgroup that
    # DOES exist succeeds and applies the mutation.
    real_name = ctx.unique_name("sim2real-behav-wg-real-")
    athena.create_work_group(Name=real_name, Description="orig")
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=real_name))

    athena.update_work_group(
        WorkGroup=real_name,
        Description="should apply",
        ConfigurationUpdates={"EnforceWorkGroupConfiguration": True},
    )
    wg = athena.get_work_group(WorkGroup=real_name)["WorkGroup"]
    assert wg["Description"] == "should apply", wg["Description"]
    assert wg["Configuration"]["EnforceWorkGroupConfiguration"] is True, wg["Configuration"]


def _error(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
