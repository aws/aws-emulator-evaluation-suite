"""get-cluster-malformed-and-missing-identifier-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-cluster-malformed-and-missing-identifier-rejected"
GROUP = "overly-permissive"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCluster rejects a malformed identifier with ValidationException, and once a real cluster
    has been fully deleted the same identifier flips to ResourceNotFoundException, while it still
    succeeds for a real, live cluster."""
    dsql = ctx.client("dsql")

    # Boundary 1: identifier doesn't match the required shape at all.
    malformed_code, malformed_message = _error(lambda: dsql.get_cluster(identifier="not-a-valid-identifier!!"))
    assert malformed_code == "ValidationException", malformed_code
    assert malformed_message == "1 validation error detected: Value at 'identifier' failed to satisfy constraint: Member must satisfy regular expression pattern: [a-z0-9]{26}", malformed_message

    # Positive control: a real, live cluster is fetched successfully.
    created = dsql.create_cluster(deletionProtectionEnabled=False)
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))
    _poll_until(
        lambda: dsql.get_cluster(identifier=identifier)["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    got = dsql.get_cluster(identifier=identifier)
    assert got["identifier"] == identifier, got["identifier"]

    # Boundary 2: the same well-formed identifier, once the cluster is fully deleted, resolves to
    # ResourceNotFoundException. (A hand-mutated well-formed-looking id is NOT used here: DSQL
    # applies structural checks beyond the bare [a-z0-9]{26} pattern, so a fabricated id can flip
    # unpredictably between ValidationException and ResourceNotFoundException depending on which
    # character changed — only a real, now-deleted id reliably exercises this boundary.)
    dsql.delete_cluster(identifier=identifier)

    def _probe():
        try:
            return dsql.get_cluster(identifier=identifier)["status"]
        except Exception as exc:  # noqa: BLE001 - narrowed below
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "DELETED"
            raise

    final_status = _poll_until(_probe, lambda s: s == "DELETED", timeout_s=300.0, interval_s=5.0)
    assert final_status == "DELETED", final_status

    missing_code, missing_message = _error(lambda: dsql.get_cluster(identifier=identifier))
    assert missing_code == "ResourceNotFoundException", missing_code
    assert missing_message == (
        f"The resource with ARN {created["arn"]} doesn't exist. Verify the ARN and try again."
    ), missing_message

    # The dead id must reject a mutation too, not just a read.
    mutate_code, mutate_message = _error(
        lambda: dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
    )
    assert mutate_code == "ResourceNotFoundException", mutate_code
    assert mutate_message == (
        f"The resource with ARN {created["arn"]} doesn't exist. Verify the ARN and try again."
    ), mutate_message


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


def _delete_cluster(ctx, identifier):
    from botocore.exceptions import ClientError

    dsql = ctx.client("dsql")
    try:
        dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
