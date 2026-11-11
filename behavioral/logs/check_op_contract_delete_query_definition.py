"""op-contract-delete-query-definition."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-query-definition"
GROUP = "error-semantics"
SERVICES = ["logs"]


def _logs_refusal(text, code, message):
    """`text` with the suffix CloudWatch Logs appends to a refusal. Only the per-call request id is
    read from `message`, and only in its 36-character form."""
    found = re.search(r"; Request ID: ([0-9a-f-]{36}); Proxy: null\)$", message or "")
    request_id = found.group(1) if found else "<no request id>"
    return (
        f"{text} (Service: AWSLogs; Status Code: 400; Error Code: {code}; "
        f"Request ID: {request_id}; Proxy: null)"
    )


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteQueryDefinition returns success and removes the definition from DescribeQueryDefinitions;
    a second delete of the same id is refused with ResourceNotFoundException and its message.
    """
    logs = ctx.client("logs")
    query_name = ctx.unique_name("sim2real-behav-qd-")

    put_resp = logs.put_query_definition(
        name=query_name, queryString="fields @timestamp, @message | limit 20"
    )
    query_definition_id = put_resp["queryDefinitionId"]
    ctx.on_cleanup(
        lambda: _safe_call(lambda: logs.delete_query_definition(queryDefinitionId=query_definition_id))
    )

    resp = logs.describe_query_definitions(queryDefinitionNamePrefix=query_name)
    ids = [q["queryDefinitionId"] for q in resp["queryDefinitions"]]
    assert query_definition_id in ids, "query definition not visible after PutQueryDefinition"

    delete_resp = logs.delete_query_definition(queryDefinitionId=query_definition_id)
    assert delete_resp["success"] is True

    resp = logs.describe_query_definitions(queryDefinitionNamePrefix=query_name)
    ids = [q["queryDefinitionId"] for q in resp["queryDefinitions"]]
    assert query_definition_id not in ids, "query definition still present after delete"

    # error boundary: a mutation on the deleted id also fails -- the identical id that
    # was just deleted, not an arbitrary unknown one, so this proves genuine deletion
    # rather than merely rejecting id shapes that were never allocated.
    code, message = _error(lambda: logs.delete_query_definition(queryDefinitionId=query_definition_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    # Only the per-request backend Request ID in the message varies.
    expected = _logs_refusal("Query definition id is invalid.", "ResourceNotFoundException", message)
    assert message == expected, (
        f"expected not-found message {expected!r}, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). Raises if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message") or ""
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
