"""delete-query-definition-removes-resource."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-query-definition-removes-resource"
GROUP = 'query-definitions'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteQueryDefinition removes the definition from DescribeQueryDefinitions, and
    the dead id itself is no longer a valid target for a second delete."""
    svc = ctx.client("logs")
    qd_name = ctx.unique_name("sim2real-behav-qd-del-")
    resp = svc.put_query_definition(
        name=qd_name,
        queryString="fields @timestamp, @message | limit 5",
    )
    qd_id = resp["queryDefinitionId"]

    described = svc.describe_query_definitions(queryDefinitionNamePrefix=qd_name)
    ids_before = [q["queryDefinitionId"] for q in described.get("queryDefinitions", [])]
    assert qd_id in ids_before, f"query definition {qd_id} not visible after put, saw {ids_before}"

    svc.delete_query_definition(queryDefinitionId=qd_id)

    described = svc.describe_query_definitions(queryDefinitionNamePrefix=qd_name)
    ids_after = [q["queryDefinitionId"] for q in described.get("queryDefinitions", [])]
    assert qd_id not in ids_after, f"query definition {qd_id} still present after delete"

    try:
        svc.delete_query_definition(queryDefinitionId=qd_id)
        raise AssertionError(f"second delete of dead id {qd_id} unexpectedly succeeded")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException deleting dead id {qd_id}, got {code}"
        )
        # Only the per-request backend Request ID in the message varies, so it is read back.
        message = exc.response["Error"].get("Message") or ""
        request_id = message.rpartition("Request ID: ")[2].removesuffix("; Proxy: null)")
        request_id = request_id if re.fullmatch(r"[0-9a-f-]{36}", request_id) else "<request id>"
        expected = (
            "Query definition id is invalid. (Service: AWSLogs; Status Code: 400; Error Code: "
            f"ResourceNotFoundException; Request ID: {request_id}; Proxy: null)"
        )
        assert message == expected, (
            f"unexpected not-found message deleting dead id {qd_id}: {message!r}"
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
