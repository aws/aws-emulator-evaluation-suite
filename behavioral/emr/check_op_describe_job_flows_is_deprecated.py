"""op-describe-job-flows-is-deprecated."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-describe-job-flows-is-deprecated"
GROUP = 'overly-permissive'
SERVICES = ['emr']

UNKNOWN_CLUSTER_ID = "j-" + "Z" * 13

def _error(fn):
    """Invoke *fn*, asserting it is rejected; return the (code, message) pair."""
    try:
        fn()
    except Exception as exc:
        err = (getattr(exc, "response", {}) or {}).get("Error", {})
        return err.get("Code", type(exc).__name__), err.get("Message", "")
    raise AssertionError("expected the operation to be rejected, but it succeeded")


_DEPRECATED = (
    "DescribeJobFlows API is deprecated. Please refer to "
    "http://docs.aws.amazon.com/ElasticMapReduce/latest/API/API_DescribeJobFlows.html for further information."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeJobFlows is deprecated: EMR refuses it with ValidationException and its exact
    deprecation message, with or without arguments, rather than serving job-flow data."""
    emr = ctx.client("emr")

    # Positive control: rules out broken auth or an IAM deny as the cause of the refusals.
    control = emr.list_clusters()
    assert "Clusters" in control, "list_clusters (positive control) did not respond as expected"

    code, message = _error(
        lambda: emr.describe_job_flows(JobFlowIds=[UNKNOWN_CLUSTER_ID])
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == _DEPRECATED, f"expected the message {_DEPRECATED!r}, got {message!r}"

    # Even an argument-free call must be refused (it is not a general lister).
    code, message = _error(lambda: emr.describe_job_flows())
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == _DEPRECATED, f"expected the message {_DEPRECATED!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
