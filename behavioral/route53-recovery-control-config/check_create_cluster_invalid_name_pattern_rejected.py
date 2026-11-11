"""create-cluster-invalid-name-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-cluster-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53-recovery-control-config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:route53-arc-cluster")
def run(ctx) -> None:
    """ClusterName must match ^\\S+$ (no whitespace); a name containing a space is
    rejected (empirically BadRequestException, not the documented ValidationException),
    no cluster is created for it, and a whitespace-free name still succeeds."""
    client = ctx.client("route53-recovery-control-config")

    invalid_name = ctx.unique_name("sim2real-r53arc-bad name-")
    code, message = _error(lambda: client.create_cluster(ClusterName=invalid_name))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected_message = (
        'Invalid request body : [ECMA 262 regex "^((?![;\'\\s<>&"])[\\u0021-\\u007E])+$" '
        f'does not match input string "{invalid_name}"]'
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # effect is absent: no cluster with that (or any prefix-matching) name exists
    matches = [c for c in client.list_clusters()["Clusters"] if c["Name"] == invalid_name]
    assert matches == [], f"expected no cluster named {invalid_name!r}, found {matches!r}"

    # positive control: a whitespace-free name succeeds
    valid_name = ctx.unique_name("sim2real-r53arc-goodname-")
    valid_arn = _create_cluster_with_retry(client, valid_name)
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(client, valid_arn))
    described_name = client.describe_cluster(ClusterArn=valid_arn)["Cluster"]["Name"]
    assert described_name == valid_name, f"expected {valid_name!r}, got {described_name!r}"


# ===== helpers =====
def _create_cluster_with_retry(client, name, timeout_s=60.0, interval_s=10.0):
    """CreateCluster, retrying ServiceQuotaExceededException for a bounded window —
    the account's 2-cluster quota may still be draining an async delete from a
    prior check's teardown."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return client.create_cluster(
                ClusterName=name, Tags={"sim2real-check": "create-cluster-invalid-name-pattern-rejected"}
            )["Cluster"]["ClusterArn"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ServiceQuotaExceededException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_cluster_and_wait(client, cluster_arn, timeout_s=300.0, interval_s=2.0) -> None:
    """Delete a cluster and block until it's actually gone — the account's cluster
    quota (2) is only freed once deletion truly completes, not when DeleteCluster
    returns, so the NEXT check that needs a fresh cluster must wait for this one."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            client.delete_cluster(ClusterArn=cluster_arn)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            # refused while the cluster's control panels are still being deleted
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            client.describe_cluster(ClusterArn=cluster_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} was not deleted within {timeout_s}s")


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator
    accepting what AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
