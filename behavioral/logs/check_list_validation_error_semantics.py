"""list-validation-error-semantics."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-validation-error-semantics"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']


def _reject_code(fn):
    """Call fn(); return the service's error (Code, Message)."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The service refuses an unknown groupBy, a pattern segment under 3 characters and maxResults=501
    with InvalidParameterException and its exact validation message, and an unknown queryId with an
    empty-message AccessDeniedException; a well-formed ListAggregateLogGroupSummaries succeeds.
    """
    svc = ctx.client("logs")

    # ListAggregateLogGroupSummaries: groupBy is REQUIRED and constrained to exactly two
    # documented enum values; botocore does not validate enum membership locally, so an
    # unrecognized value must be rejected by the service.
    code_groupby, msg_groupby = _reject_code(
        lambda: svc.list_aggregate_log_group_summaries(groupBy="NOT_A_REAL_GROUPING")
    )
    assert code_groupby == "InvalidParameterException", (
        f"ListAggregateLogGroupSummaries(groupBy=<invalid>): expected InvalidParameterException, "
        f"got {code_groupby!r}"
    )
    expected = (
        "1 validation error detected: Value at 'groupBy' failed to satisfy constraint: Member must "
        "satisfy enum value set: [DATA_SOURCE_NAME_AND_TYPE, DATA_SOURCE_NAME_TYPE_AND_FORMAT]"
    )
    assert msg_groupby == expected, f"expected message {expected!r}, got {msg_groupby!r}"

    # logGroupNamePattern must match `(seg){3,24}(\\|(seg){3,24}){0,4}`; "ab|cde" clears the
    # OVERALL min/max length botocore checks locally (6 chars, well inside 3-129) but its first
    # segment is only 2 characters, violating the per-segment 3-24 constraint that only the
    # service's own regex enforces.
    code_pattern, msg_pattern = _reject_code(
        lambda: svc.list_aggregate_log_group_summaries(
            groupBy="DATA_SOURCE_NAME_AND_TYPE", logGroupNamePattern="ab|cde"
        )
    )
    assert code_pattern == "InvalidParameterException", (
        f"ListAggregateLogGroupSummaries(logGroupNamePattern='ab|cde', first segment below the "
        f"documented per-segment minimum of 3 characters): expected InvalidParameterException, "
        f"got {code_pattern!r}"
    )
    expected = (
        "1 validation error detected: Value at 'logGroupNamePattern' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: "
        "(\\^?[\\.\\-_\\/#A-Za-z0-9]{3,512})|(\\^?[\\.\\-_\\/#A-Za-z0-9]{3,24})"
        "(\\|\\^?[\\.\\-_\\/#A-Za-z0-9]{3,24}){0,4}"
    )
    assert msg_pattern == expected, f"expected message {expected!r}, got {msg_pattern!r}"

    # A well-formed call (valid groupBy, no filters) must still succeed.
    ok = svc.list_aggregate_log_group_summaries(groupBy="DATA_SOURCE_NAME_AND_TYPE")
    assert "aggregateLogGroupSummaries" in ok, f"expected a well-formed call to succeed: {ok!r}"

    # ListLogGroupsForQuery: queryId is REQUIRED; a well-formed-but-nonexistent
    # queryId must be rejected, not silently return an empty log-group list.
    fake_query_id = str(uuid.uuid4())
    code_query, msg_query = _reject_code(lambda: svc.list_log_groups_for_query(queryId=fake_query_id))
    assert code_query == "AccessDeniedException", (
        f"ListLogGroupsForQuery(queryId=<nonexistent>): expected AccessDeniedException, got {code_query!r}"
    )
    # AWS sends this refusal with an empty message.
    assert msg_query == "", f"expected an empty message, got {msg_query!r}"

    # maxResults is constrained to [50, 500]; botocore's local validator only checks the LOWER
    # bound (range_check has no upper-bound branch), so 501 clears it locally and it is the
    # service's own upper-bound enforcement that gets exercised and asserted here.
    code_maxresults, msg_maxresults = _reject_code(
        lambda: svc.list_log_groups_for_query(queryId=fake_query_id, maxResults=501)
    )
    assert code_maxresults == "InvalidParameterException", (
        f"ListLogGroupsForQuery(maxResults=501, above the documented maximum of 500): expected "
        f"InvalidParameterException, got {code_maxresults!r}"
    )
    expected = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 500"
    )
    assert msg_maxresults == expected, f"expected message {expected!r}, got {msg_maxresults!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
