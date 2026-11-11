"""set-unhealthy-node-replacement-error-not-swallowed."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-unhealthy-node-replacement-error-not-swallowed"
GROUP = "error-semantics"
SERVICES = ["emr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetUnhealthyNodeReplacement on a nonexistent JobFlowId fails with ValidationException and its exact
    message, and DescribeCluster on that id then fails with InvalidRequestException and its exact message."""
    emr = ctx.client("emr")
    bogus_id = "j-" + uuid.uuid4().hex[:13].upper()

    expected_message = f"Cluster id '{bogus_id}' is not valid."

    code, message = _error(
        lambda: emr.set_unhealthy_node_replacement(
            JobFlowIds=[bogus_id], UnhealthyNodeReplacement=True
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    describe_code, describe_message = _error(lambda: emr.describe_cluster(ClusterId=bogus_id))
    assert describe_code == "InvalidRequestException", (
        "DescribeCluster on the same nonexistent id must independently reject it too, "
        f"as evidence no cluster was fabricated; got {describe_code!r}"
    )
    assert describe_message == expected_message, (
        f"expected DescribeCluster message {expected_message!r}, got {describe_message!r}"
    )


def _error(fn):
    """The (code, message) of the expected rejection; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
