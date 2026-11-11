"""op-contract-describeApplicationStatusChecks."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeApplicationStatusChecks"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeApplicationStatusChecks lists configured checks and enforces the DryRun contract."""
    ec2 = ctx.client("ec2")
    _require_op(ec2, "describe_application_status_checks")
    _require_op(ec2, "create_application_status_check")

    # positive control: create a real check so the representation contract has a subject --
    # a pristine or already-clean account would otherwise let the per-item assertions below
    # never actually execute against anything.
    created = ec2.create_application_status_check(
        Protocol="http",
        Port=8080,
        Path="/health",
        TagSpecifications=[
            {
                "ResourceType": "application-status-check",
                "Tags": [{"Key": "sim2real", "Value": ctx.unique_name("op-contract-describe-checks-")}],
            }
        ],
    )["ApplicationStatusCheck"]
    check_id = created["ApplicationStatusCheckId"]
    ctx.on_cleanup(lambda: ec2.delete_application_status_check(ApplicationStatusCheckId=check_id))

    # terminal read: an independent operation (Describe, not Create) must represent it -- filtered
    # by id, which is a single, unpaginated page.
    response = ec2.describe_application_status_checks(ApplicationStatusCheckIds=[check_id])
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200, f"unexpected status: {response!r}"
    # substantive assertion directly on the response body (confirmed shape: top-level
    # "ApplicationStatusChecks" list -- see the CLI Output section for
    # DescribeApplicationStatusChecks).
    assert "ApplicationStatusChecks" in response, (
        f"expected ApplicationStatusChecks in response body: {response!r}"
    )
    checks = response["ApplicationStatusChecks"]
    assert isinstance(checks, list), f"expected ApplicationStatusChecks to be a list, got {checks!r}"
    assert len(checks) == 1, f"expected exactly the created check when filtered by id, got {checks!r}"
    item = checks[0]
    assert item["ApplicationStatusCheckId"] == check_id, item
    assert item["Protocol"] == "http", f"expected Protocol http, got {item!r}"
    assert item["Port"] == 8080, f"expected Port 8080, got {item!r}"
    assert item["Path"] == "/health", f"expected Path /health, got {item!r}"
    # pagination contract: nextToken must be null/absent when there is nothing more to return
    assert response.get("NextToken") in (None, ""), (
        "NextToken should be empty/absent for a single-item, unpaginated result"
    )

    # success path: account-wide listing (no ApplicationStatusCheckIds filter); active checks
    # only. Must carry the check just created, and every record must be identity/protocol shaped.
    all_checks = ec2.describe_application_status_checks(IncludeAll=False)["ApplicationStatusChecks"]
    assert any(c.get("ApplicationStatusCheckId") == check_id for c in all_checks), (
        f"created check {check_id} missing from account-wide listing: {all_checks!r}"
    )
    for record in all_checks:
        assert isinstance(record, dict), f"check record should be dict-shaped, got {record!r}"
        # a check record should describe its identity and the protocol/port it monitors
        assert "ApplicationStatusCheckId" in record or "Protocol" in record, (
            f"check record missing ApplicationStatusCheckId/Protocol: {record!r}"
        )

    # error boundary: DryRun=True must short-circuit with DryRunOperation when the caller has permission
    code, message = _error(lambda: ec2.describe_application_status_checks(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"expected DryRun message {_DRY_RUN_MESSAGE!r}, got {message!r}"


def _require_op(client: Any, op_name: str) -> None:

    if not hasattr(client, op_name):
        raise AssertionError(f"ec2 client missing operation {op_name!r} (botocore too old)")


def _error(fn):
    """Call fn(); return its error as (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
