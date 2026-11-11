"""archive-rule-lifecycle-crud."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "archive-rule-lifecycle-crud"
GROUP = "state-machine"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """An archive rule's filter is stored on creation, changes on UpdateArchiveRule, and
    the rule disappears after DeleteArchiveRule."""
    aa = ctx.client("accessanalyzer")
    analyzer_name = ctx.unique_name("sim2real-aa-archrule-")
    aa.create_analyzer(
        analyzerName=analyzer_name, type="ACCOUNT", tags={"sim2real": "archive-rule-lifecycle-crud"}
    )
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=analyzer_name))
    _poll_analyzer_status(ctx, analyzer_name)

    rule_name = ctx.unique_name("sim2real-aa-rule-")
    initial_filter = {"resourceType": {"eq": ["AWS::S3::Bucket"]}}
    aa.create_archive_rule(analyzerName=analyzer_name, ruleName=rule_name, filter=initial_filter)

    fetched = aa.get_archive_rule(analyzerName=analyzer_name, ruleName=rule_name)["archiveRule"]
    assert fetched["filter"] == initial_filter, fetched["filter"]

    updated_filter = {"isPublic": {"eq": ["true"]}}
    aa.update_archive_rule(analyzerName=analyzer_name, ruleName=rule_name, filter=updated_filter)

    fetched_after_update = aa.get_archive_rule(analyzerName=analyzer_name, ruleName=rule_name)["archiveRule"]
    assert fetched_after_update["filter"] == updated_filter, fetched_after_update["filter"]

    aa.delete_archive_rule(analyzerName=analyzer_name, ruleName=rule_name)
    code, message = _error(lambda: aa.get_archive_rule(analyzerName=analyzer_name, ruleName=rule_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Archive rule not found", message

    update_code, update_message = _error(
        lambda: aa.update_archive_rule(analyzerName=analyzer_name, ruleName=rule_name, filter=updated_filter)
    )
    assert update_code == "ResourceNotFoundException", (
        f"a mutation on a deleted archive rule must also be rejected, got {update_code}"
    )
    assert update_message == "Archive rule not found", update_message

    aa.create_archive_rule(analyzerName=analyzer_name, ruleName=rule_name, filter=initial_filter)
    recreated = aa.get_archive_rule(analyzerName=analyzer_name, ruleName=rule_name)["archiveRule"]
    assert recreated["filter"] == initial_filter, (
        f"a deleted archive rule's name must be reusable, got {recreated['filter']}"
    )


def _poll_analyzer_status(ctx, name: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    aa = ctx.client("accessanalyzer")
    deadline = time.monotonic() + timeout_s
    status = "CREATING"
    while time.monotonic() < deadline:
        status = aa.get_analyzer(analyzerName=name)["analyzer"]["status"]
        if status != "CREATING":
            return status
        time.sleep(interval_s)
    return status


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a target
    accepting what AWS refuses cannot be read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
