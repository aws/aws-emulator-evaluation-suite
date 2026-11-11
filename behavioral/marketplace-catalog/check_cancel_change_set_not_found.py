"""cancel-change-set-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-change-set-not-found"
GROUP = "error-semantics"
SERVICES = ["marketplace-catalog"]
CATALOG_PATTERN = r"^(?![.-])(?!.*[.-]{2})(?![0-9]+\.[0-9.]+$)[a-zA-Z0-9.-]{1,47}(?<![.-])$"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelChangeSet refuses a Catalog outside the pattern with ValidationException and a nonexistent
    ChangeSetId with ResourceNotFoundException, DescribeChangeSet on that id is also not found, and
    ListChangeSets still works.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    missing_id = "sim2real" + ctx.unique_name("").replace("-", "")[:16]

    code0, msg0 = _error_code(
        lambda: mp.cancel_change_set(Catalog="AWS_Marketplace", ChangeSetId=missing_id)
    )
    assert code0 == "ValidationException", f"expected ValidationException, got {code0}: {msg0}"
    assert msg0 == (
        f"[Requested catalog 'AWS_Marketplace' is invalid. It should match with {CATALOG_PATTERN}.]"
    ), msg0

    code, msg = _error_code(
        lambda: mp.cancel_change_set(Catalog="AWSMarketplace", ChangeSetId=missing_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {msg}"
    assert msg == f"Requested change set '{missing_id}' does not exist.", msg

    code2, msg2 = _error_code(
        lambda: mp.describe_change_set(Catalog="AWSMarketplace", ChangeSetId=missing_id)
    )
    assert code2 == "ResourceNotFoundException", (
        f"no change set should have been created, got {code2}: {msg2}"
    )
    assert msg2 == f"Requested change set '{missing_id}' does not exist.", msg2

    resp = mp.list_change_sets(Catalog="AWSMarketplace")
    assert "ChangeSetSummaryList" in resp, f"ListChangeSets should still succeed, got {resp}"


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
