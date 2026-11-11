"""op-contract-describe-query-definitions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-query-definitions"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeQueryDefinitions: success path filters saved query definitions by
    queryDefinitionNamePrefix and returns exact queryString content; error boundary is
    InvalidParameterException when maxResults exceeds the documented maximum of 1000."""
    logs = ctx.client("logs")
    prefix = ctx.unique_name("sim2real-behav-qd-")
    name_a = f"{prefix}alpha"
    name_b = f"{prefix}beta"
    query_string = "fields @timestamp, @message | limit 10"

    id_a = logs.put_query_definition(name=name_a, queryString=query_string)["queryDefinitionId"]
    id_b = logs.put_query_definition(name=name_b, queryString=query_string)["queryDefinitionId"]
    ctx.on_cleanup(lambda: logs.delete_query_definition(queryDefinitionId=id_a))
    ctx.on_cleanup(lambda: logs.delete_query_definition(queryDefinitionId=id_b))

    resp = logs.describe_query_definitions(queryDefinitionNamePrefix=prefix)
    by_id = {q["queryDefinitionId"]: q for q in resp["queryDefinitions"]}
    assert id_a in by_id and id_b in by_id, "both query definitions should be listed by prefix"
    assert by_id[id_a]["queryString"] == query_string, (
        f"expected queryString {query_string!r}, got {by_id[id_a]['queryString']!r}"
    )
    assert by_id[id_a]["name"] == name_a, f"expected name {name_a!r}, got {by_id[id_a]['name']!r}"

    # positive control: a maxResults value inside the documented 1..1000 range must be
    # accepted, so the error boundary below cannot be satisfied by a target that rejects
    # every maxResults value rather than specifically values above the maximum.
    in_range_resp = logs.describe_query_definitions(
        queryDefinitionNamePrefix=prefix, maxResults=1
    )
    assert len(in_range_resp["queryDefinitions"]) == 1, (
        f"expected maxResults=1 to cap the result at 1 item, "
        f"got {len(in_range_resp['queryDefinitions'])}"
    )

    # error boundary: maxResults above the documented maximum of 1000
    code, message = _expect_error(
        lambda: logs.describe_query_definitions(
            queryDefinitionNamePrefix=prefix, maxResults=1001
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected = "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: Member must have value less than or equal to 1000"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _expect_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
