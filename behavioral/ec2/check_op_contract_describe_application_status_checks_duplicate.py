"""op-contract-describe-application-status-checks-duplicate."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-application-status-checks-duplicate"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeApplicationStatusChecks filtered by ID returns a created check's protocol, port and path;
    after delete it is absent from the default view but listed with DeletionTime under
    IncludeAll=True; DryRun answers DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")
    _require_op(ec2, "describe_application_status_checks")
    _require_op(ec2, "create_application_status_check")
    _require_op(ec2, "delete_application_status_check")

    # positive control: create a real check so the representation/visibility assertions below have
    # a subject -- a pristine account would otherwise let every assertion pass vacuously.
    created = ec2.create_application_status_check(
        Protocol="https",
        Port=443,
        Path="/status",
        TagSpecifications=[
            {
                "ResourceType": "application-status-check",
                "Tags": [{"Key": "sim2real", "Value": ctx.unique_name("op-contract-describe-checks-dup-")}],
            }
        ],
    )["ApplicationStatusCheck"]
    check_id = created["ApplicationStatusCheckId"]
    ctx.on_cleanup(lambda: ec2.delete_application_status_check(ApplicationStatusCheckId=check_id))

    # terminal read #1: an independent operation (Describe, not Create) must represent the live
    # check, filtered by id -- a single, unpaginated page, with no DeletionTime yet.
    response = ec2.describe_application_status_checks(ApplicationStatusCheckIds=[check_id])
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200, f"unexpected status: {response!r}"
    assert "ApplicationStatusChecks" in response, (
        f"expected ApplicationStatusChecks in response body: {response!r}"
    )
    checks = response["ApplicationStatusChecks"]
    assert isinstance(checks, list), f"expected ApplicationStatusChecks to be a list, got {checks!r}"
    assert len(checks) == 1, f"expected exactly the created check when filtered by id, got {checks!r}"
    item = checks[0]
    assert item["ApplicationStatusCheckId"] == check_id, item
    assert item["Protocol"] == "https", f"expected Protocol https, got {item!r}"
    assert item["Port"] == 443, f"expected Port 443, got {item!r}"
    assert item["Path"] == "/status", f"expected Path /status, got {item!r}"
    assert item.get("DeletionTime") is None, f"live check should carry no DeletionTime: {item!r}"

    # mutate: delete the check through an independent operation.
    ec2.delete_application_status_check(ApplicationStatusCheckId=check_id)

    # terminal read #2 (default view): a deleted check drops out of the default
    # (IncludeAll omitted, i.e. false) response, per DescribeApplicationStatusChecks's own
    # documentation of the IncludeAll parameter.
    default_view = ec2.describe_application_status_checks(ApplicationStatusCheckIds=[check_id]).get(
        "ApplicationStatusChecks", []
    )
    assert default_view == [], f"expected deleted check absent from default view, got {default_view!r}"

    # terminal read #3 (grace-period view): the SAME deleted check remains visible under
    # IncludeAll=True during the deletion grace period, now carrying a populated DeletionTime.
    grace_view = ec2.describe_application_status_checks(
        ApplicationStatusCheckIds=[check_id], IncludeAll=True
    ).get("ApplicationStatusChecks", [])
    assert len(grace_view) == 1, (
        f"expected the deleted check still visible under IncludeAll=True during the grace period, "
        f"got {grace_view!r}"
    )
    assert grace_view[0]["ApplicationStatusCheckId"] == check_id, grace_view[0]
    assert grace_view[0].get("DeletionTime") is not None, (
        f"expected DeletionTime populated for a deleted check under IncludeAll=True: {grace_view[0]!r}"
    )

    # error boundary: DryRun=True must short-circuit with DryRunOperation when the caller has permission
    code, message = _error(lambda: ec2.describe_application_status_checks(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )


def _require_op(client: Any, op_name: str) -> None:

    if not hasattr(client, op_name):
        raise AssertionError(f"ec2 client missing operation {op_name!r} (botocore too old)")


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
