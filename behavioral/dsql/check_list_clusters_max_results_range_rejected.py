"""list-clusters-max-results-range-rejected."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "list-clusters-max-results-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListClusters with maxResults 0 or 101, sent without client-side validation, fails with
    ValidationException and the exact range message, while maxResults=5 succeeds and returns at most 5."""
    dsql = ctx.client("dsql")
    unvalidated = ctx.client("dsql", config=Config(parameter_validation=False))

    code_zero, code_zero_message = _error(lambda: unvalidated.list_clusters(maxResults=0))
    assert code_zero == "ValidationException", f"expected ValidationException, got {code_zero}"
    assert code_zero_message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    ), code_zero_message

    code_over, code_over_message = _error(lambda: unvalidated.list_clusters(maxResults=101))
    assert code_over == "ValidationException", f"expected ValidationException, got {code_over}"
    assert code_over_message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    ), code_over_message

    ok = dsql.list_clusters(maxResults=5)
    assert len(ok["clusters"]) <= 5, f"expected <=5 clusters, got {len(ok['clusters'])}"


def _error(fn):
    """Call fn() and return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
