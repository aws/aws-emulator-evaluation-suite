"""apply-maintenance-action-missing-resource-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apply-maintenance-action-missing-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["docdb-elastic"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ApplyPendingMaintenanceAction against a syntactically valid but nonexistent
    resourceArn returns ResourceNotFoundException; ListPendingMaintenanceActions (a
    call that always succeeds) still works on the same client (positive control)."""
    client = ctx.client("docdb-elastic")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_resource_arn = (
        f"arn:aws:docdb-elastic:{ctx.region}:{account_id}:"
        "cluster/00000000-0000-0000-0000-000000000000"
    )

    code, message = _error(
        lambda: client.apply_pending_maintenance_action(
            resourceArn=fake_resource_arn,
            applyAction="system-update",
            optInType="IMMEDIATE",
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Unable to find the cluster", f"unexpected message: {message!r}"

    # effect absent: no pending-action record was created for a resource that never existed
    listing = client.list_pending_maintenance_actions(maxResults=100)
    arns = [p["resourceArn"] for p in listing.get("resourcePendingMaintenanceActions", [])]
    assert fake_resource_arn not in arns, (
        f"a pending action was recorded against a nonexistent resource: {fake_resource_arn}"
    )

    # positive control: a well-formed, harmless call on the same client succeeds
    resp = client.list_pending_maintenance_actions(maxResults=10)
    assert "resourcePendingMaintenanceActions" in resp, (
        f"expected resourcePendingMaintenanceActions key in response, got keys {list(resp)}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
