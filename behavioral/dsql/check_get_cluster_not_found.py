"""get-cluster-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-cluster-not-found"
GROUP = "error-semantics"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a cluster is fully DELETED, GetCluster and DeleteCluster on its identifier both fail with
    ResourceNotFoundException and AWS's exact message naming the cluster ARN."""
    dsql = ctx.client("dsql")

    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real-created-with": "get-cluster-not-found", "sim2real-purpose": "behavioral-test"},
    )
    real_identifier = created["identifier"]
    ctx.on_cleanup(lambda: _best_effort_delete(dsql, real_identifier))

    _poll_until(
        lambda: dsql.get_cluster(identifier=real_identifier)["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    real = dsql.get_cluster(identifier=real_identifier)
    assert real["identifier"] == real_identifier, f"expected {real_identifier}, got {real.get('identifier')!r}"

    dsql.delete_cluster(identifier=real_identifier)

    def _probe():
        try:
            return dsql.get_cluster(identifier=real_identifier)["status"]
        except Exception as exc:  # noqa: BLE001 - narrowed below
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "DELETED"
            raise

    final_status = _poll_until(_probe, lambda s: s == "DELETED", timeout_s=300.0, interval_s=5.0)
    assert final_status == "DELETED", f"expected DELETED, last status {final_status!r}"

    code, message = _error(lambda: dsql.get_cluster(identifier=real_identifier))
    assert code == "ResourceNotFoundException", code
    assert message == (
        f"The resource with ARN {created["arn"]} doesn't exist. Verify the ARN and try again."
    ), message

    # A mutation on the dead id must also fail, not just the read.
    mutation_code, mutation_message = _error(lambda: dsql.delete_cluster(identifier=real_identifier))
    assert mutation_code == "ResourceNotFoundException", mutation_code
    assert mutation_message == (
        f"The resource with ARN {created["arn"]} doesn't exist. Verify the ARN and try again."
    ), mutation_message


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn() and return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete(dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


