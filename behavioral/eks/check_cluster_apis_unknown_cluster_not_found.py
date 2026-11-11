"""cluster-apis-unknown-cluster-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _expect_error(fn):
    """Call fn, require that it raises, return (ErrorCode, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")

CHECK = "cluster-apis-unknown-cluster-not-found"
GROUP = 'error-semantics'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Cluster-scoped APIs on a name that was never created all raise ResourceNotFoundException."""
    c = ctx.client("eks")
    bogus = ctx.unique_name("sim2real-behav-eks-ghost-")

    calls = {
        "DescribeCluster": lambda: c.describe_cluster(name=bogus),
        "DeleteCluster": lambda: c.delete_cluster(name=bogus),
        "UpdateClusterConfig": lambda: c.update_cluster_config(
            name=bogus,
            logging={"clusterLogging": [{"types": ["api"], "enabled": True}]},
        ),
        "UpdateClusterVersion": lambda: c.update_cluster_version(
            name=bogus, version="1.31"
        ),
    }
    expected_message = f"No cluster found for name: {bogus}."
    for op, fn in calls.items():
        code, message = _expect_error(fn)
        assert code == "ResourceNotFoundException", (
            f"{op} on unknown cluster: expected ResourceNotFoundException, got {code!r}"
        )
        assert message == expected_message, (
            f"{op} on unknown cluster: expected message {expected_message!r}, got {message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
