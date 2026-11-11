"""op-contract-putQueryDefinition."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-putQueryDefinition"
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
    """PutQueryDefinition returns an id that DescribeQueryDefinitions lists with its name and query and
    that updates in place; after delete, a Put to that id gets ResourceNotFoundException.
    """
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-qd-")
    query_string = "fields @timestamp, @message | sort @timestamp desc | limit 20"

    resp = logs.put_query_definition(name=name, queryString=query_string)
    query_definition_id = resp["queryDefinitionId"]
    assert query_definition_id, "expected a server-generated queryDefinitionId"

    def _cleanup():
        try:
            logs.delete_query_definition(queryDefinitionId=query_definition_id)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    described = logs.describe_query_definitions(queryDefinitionNamePrefix=name)
    matches = [
        q for q in described["queryDefinitions"] if q["queryDefinitionId"] == query_definition_id
    ]
    assert len(matches) == 1, f"expected exactly one query definition, got {matches}"
    assert matches[0]["name"] == name, f"expected name {name!r}, got {matches[0]['name']!r}"
    assert matches[0]["queryString"] == query_string, (
        f"expected queryString {query_string!r}, got {matches[0]['queryString']!r}"
    )

    # Update in place: same queryDefinitionId, new queryString, no new id minted.
    new_query_string = "fields @timestamp, @message | limit 5"
    update_resp = logs.put_query_definition(
        name=name, queryString=new_query_string, queryDefinitionId=query_definition_id
    )
    assert update_resp["queryDefinitionId"] == query_definition_id, (
        "updating an existing query definition must preserve its id"
    )
    described_after = logs.describe_query_definitions(queryDefinitionNamePrefix=name)
    after = [
        q
        for q in described_after["queryDefinitions"]
        if q["queryDefinitionId"] == query_definition_id
    ]
    assert len(after) == 1, f"expected exactly one query definition after update, got {after}"
    assert after[0]["queryString"] == new_query_string, (
        f"expected queryString {new_query_string!r} after update, got {after[0]['queryString']!r}"
    )

    # Delete proves gone: an independent read does not list the id, and a
    # distinct error boundary emerges — a Put targeting that deleted id is
    # rejected with the specific not-found code rather than resurrecting it.
    logs.delete_query_definition(queryDefinitionId=query_definition_id)
    described_gone = logs.describe_query_definitions(queryDefinitionNamePrefix=name)
    remaining = [
        q for q in described_gone["queryDefinitions"] if q["queryDefinitionId"] == query_definition_id
    ]
    assert remaining == [], f"expected {query_definition_id} gone after delete, still found {remaining}"

    code, message = _client_error(
        lambda: logs.put_query_definition(
            name=name, queryString=query_string, queryDefinitionId=query_definition_id
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating a deleted queryDefinitionId, got {code}"
    )
    # Only the per-request backend Request ID in the message varies.
    expected = _logs_refusal(
        "Query definition id is invalid. If you are updating query definition, please provide "
        "correct query definition id; If you are creating new query definition, do not use "
        "--query-definition-id as a parameter",
        "ResourceNotFoundException",
        message,
    )
    assert message == expected, (
        f"expected not-found message {expected!r}, got {message!r}"
    )


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
