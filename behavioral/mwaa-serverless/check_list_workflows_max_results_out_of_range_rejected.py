"""list-workflows-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-workflows-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["mwaa-serverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListWorkflows refuses MaxResults 101 and 0 (outside the documented 1-100) with a server-side
    ValidationException and its exact message, while MaxResults=1 returns at most one workflow.
    """
    mwaa = ctx.client("mwaa-serverless")
    unvalidated = ctx.client("mwaa-serverless", config=Config(parameter_validation=False))

    # Positive control: MaxResults=1 succeeds through both the validated and unvalidated client.
    resp = mwaa.list_workflows(MaxResults=1)
    assert len(resp["Workflows"]) <= 1, f"expected at most 1 workflow, got {resp['Workflows']!r}"
    resp_unvalidated = unvalidated.list_workflows(MaxResults=1)
    assert len(resp_unvalidated["Workflows"]) <= 1, (
        f"expected at most 1 workflow via unvalidated client, got {resp_unvalidated['Workflows']!r}"
    )

    # Break exactly one thing: MaxResults above the documented ceiling.
    code_over, msg_over = _error(lambda: unvalidated.list_workflows(MaxResults=101))
    assert code_over == "ValidationException", f"expected ValidationException, got {code_over!r}"
    assert msg_over == (
        "1 validation error detected: Value '101' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    ), f"unexpected ValidationException message: {msg_over!r}"

    # Break exactly one thing: MaxResults below the documented floor.
    code_zero, msg_zero = _error(lambda: unvalidated.list_workflows(MaxResults=0))
    assert code_zero == "ValidationException", f"expected ValidationException, got {code_zero!r}"
    assert msg_zero == (
        "1 validation error detected: Value '0' at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    ), f"unexpected ValidationException message: {msg_zero!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
