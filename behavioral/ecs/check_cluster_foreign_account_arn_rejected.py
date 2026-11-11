"""cluster-foreign-account-arn-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-foreign-account-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A well-formed cluster ARN belonging to another account is a parameter error, not a not-found."""
    ecs = ctx.client("ecs")

    # Positive control: DeleteCluster against a real, owned cluster succeeds and
    # is observable at an independent read. Without this, "rejects the foreign
    # ARN" would be indistinguishable from "rejects every DeleteCluster call".
    name = ctx.unique_name("sim2real-behav-ecs-cluster-foreign-")
    ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(ecs, name))
    ecs.delete_cluster(cluster=name)
    desc = ecs.describe_clusters(clusters=[name])
    if desc["clusters"]:
        assert desc["clusters"][0]["status"] != "ACTIVE", (
            f"owned cluster {name} still ACTIVE after DeleteCluster succeeded"
        )
    else:
        assert len(desc.get("failures", [])) == 1, (
            f"expected exactly one failure entry for deleted {name}, got {desc.get('failures')}"
        )

    # Real ECS distinguishes "not yours / malformed for this account" from
    # "exists nowhere": a well-formed ARN in another account must not be
    # reported as a plain ClusterNotFound.
    foreign = f"arn:aws:ecs:{ctx.region}:111122223333:cluster/does-not-exist-xyz"
    code, message = _expect_error(
        lambda: ecs.delete_cluster(cluster=foreign),
        ("InvalidParameterException", "AccessDeniedException", "ClusterNotFoundException"),
    )
    assert code == "InvalidParameterException", (
        f"foreign-account cluster ARN: expected InvalidParameterException, got {code}"
    )
    assert message == "AccountIDs mismatch", f"foreign-account cluster ARN: unexpected message {message!r}"


# Codes that mean "the control plane is busy", never "your request was wrong".
_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "RequestLimitExceeded",
    "TooManyRequestsException",
)


def _delete_ignoring_not_found(ecs, cluster_name):
    try:
        ecs.delete_cluster(cluster=cluster_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ClusterNotFoundException":
            raise


def _expect_error(fn, allowed, attempts: int = 7):
    """Return the (code, message) raised by *fn*, retrying through throttles.

    A success raises: used by overly-permissive checks.
    """
    if isinstance(allowed, str):
        allowed = (allowed,)
    for i in range(attempts):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            if code not in _THROTTLE_CODES:
                return code, err.get("Message")
            time.sleep(min(2.0 * (2**i), 20.0))
            continue
        raise AssertionError(
            f"operation unexpectedly SUCCEEDED with {result!r}; expected one of {allowed}"
        )
    raise AssertionError(f"still throttled after {attempts} attempts; expected {allowed}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
