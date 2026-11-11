"""cluster-describe-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-describe-not-found"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_NOT_FOUND_MESSAGE = "The requested resource doesn\u2019t exist."

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _bogus_cluster_arn(ctx):
    """A well-formed MSK cluster ARN, in this account, that cannot exist."""
    return (
        f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:cluster/"
        f"{ctx.unique_name('sim2real-behav-nonexistent-')}/"
        "00000000-0000-0000-0000-000000000000-1"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeClusterV2 on a well-formed but nonexistent ClusterArn fails with NotFoundException and its
    exact message."""
    msk = ctx.client("kafka")
    code, message = _err(lambda: msk.describe_cluster_v2(ClusterArn=_bogus_cluster_arn(ctx)))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == _NOT_FOUND_MESSAGE, message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
