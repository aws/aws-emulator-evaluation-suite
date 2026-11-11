"""list-clusters-max-results-out-of-range-validation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-clusters-max-results-out-of-range-validation"
GROUP = "overly-permissive"
SERVICES = ["docdb-elastic"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListClusters rejects a maxResults value above the documented 1-100 range with
    ValidationException, while an in-range value succeeds (positive control). Neither
    branch provisions any resource, so this check always runs at full speed."""
    client = ctx.client("docdb-elastic")

    code, message = _error(lambda: client.list_clusters(maxResults=101))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        "1 validation error detected: Value '101' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    ), f"unexpected message: {message!r}"

    # positive control: an in-range maxResults succeeds
    resp = client.list_clusters(maxResults=100)
    assert "clusters" in resp, f"in-range maxResults=100 should succeed and return clusters, got keys={list(resp)}"


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected ListClusters(maxResults=101) to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
