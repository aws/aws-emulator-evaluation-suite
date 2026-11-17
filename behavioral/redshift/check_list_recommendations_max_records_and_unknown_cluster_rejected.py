"""list-recommendations-max-records-and-unknown-cluster-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-recommendations-max-records-and-unknown-cluster-rejected"
GROUP = "recommendations"
SERVICES = ["redshift"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRecommendations accepts MaxRecords=0 (the one value its range allows) and rejects a
    positive page size with InvalidParameterValue, and reports an unknown cluster with
    ClusterNotFound rather than an empty recommendation list."""
    rs = ctx.client("redshift")

    at_boundary = rs.list_recommendations(MaxRecords=0)
    assert at_boundary["Recommendations"] == [], at_boundary

    code, message = _error(lambda: rs.list_recommendations(MaxRecords=1))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}: {message!r}"
    expected = "Invalid value for max records. Must be between 0 and 0"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    missing_cluster = ctx.unique_name("sim2real-behav-rs-recs-missing-")
    code, message = _error(lambda: rs.list_recommendations(ClusterIdentifier=missing_cluster))
    assert code == "ClusterNotFound", f"expected ClusterNotFound, got {code}: {message!r}"
    expected_cluster = f"Cluster {missing_cluster} not found."
    assert message == expected_cluster, f"expected message {expected_cluster!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
