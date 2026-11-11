"""cluster-describe-malformed-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-describe-malformed-arn-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeClusterV2 with a ClusterArn that is not an ARN fails with AccessDeniedException and the
    exact message naming the caller and resource "not-an-arn", not NotFoundException."""
    msk = ctx.client("kafka")

    # Positive control: the client/credentials/service are generally healthy,
    # so the rejection below is about the malformed ARN, not about every call
    # being denied.
    msk.list_clusters_v2()

    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    code, message = _err(lambda: msk.describe_cluster_v2(ClusterArn="not-an-arn"))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    assert message == (
        f"User: {caller_arn} is not authorized to perform: kafka:DescribeClusterV2 on resource: not-an-arn"
    ), message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
