"""create-global-cluster-duplicate-identifier-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-global-cluster-duplicate-identifier-rejected"
GROUP = "global_clusters"
SERVICES = ["rds"]

ERR_ALREADY_EXISTS = "GlobalClusterAlreadyExistsFault"


def _error_code(fn):
    """The (code, message) ``fn`` raises; an unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGlobalCluster with an identifier already in use is rejected with
    GlobalClusterAlreadyExistsFault, and an unrelated identifier is still creatable."""
    rds = ctx.client("rds")
    global_id = ctx.unique_name("sim2real-behav-gc-")
    rds.create_global_cluster(GlobalClusterIdentifier=global_id, Engine="aurora-mysql")
    ctx.on_cleanup(lambda: _delete_unless_gone(rds, global_id))

    code, message = _error_code(
        lambda: rds.create_global_cluster(GlobalClusterIdentifier=global_id, Engine="aurora-mysql")
    )
    assert code == ERR_ALREADY_EXISTS, f"unexpected error code: {code!r}"
    expected = f"Global cluster {global_id} already exists"
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    # Effect absent: still exactly one global cluster under this identifier.
    described = rds.describe_global_clusters(GlobalClusterIdentifier=global_id)["GlobalClusters"]
    assert len(described) == 1, f"expected exactly one global cluster {global_id!r}, got {described!r}"

    # Positive control: an unrelated identifier is unaffected.
    other_id = ctx.unique_name("sim2real-behav-gc-other-")
    rds.create_global_cluster(GlobalClusterIdentifier=other_id, Engine="aurora-mysql")
    ctx.on_cleanup(lambda: _delete_unless_gone(rds, other_id))
    other_described = rds.describe_global_clusters(GlobalClusterIdentifier=other_id)["GlobalClusters"]
    assert len(other_described) == 1 and other_described[0]["GlobalClusterIdentifier"] == other_id, (
        f"positive control global cluster not independently readable: {other_described!r}"
    )


def _delete_unless_gone(rds, global_id: str) -> None:
    try:
        rds.delete_global_cluster(GlobalClusterIdentifier=global_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "GlobalClusterNotFoundFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
