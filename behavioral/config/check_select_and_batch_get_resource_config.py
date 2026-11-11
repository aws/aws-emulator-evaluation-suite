"""select-and-batch-get-resource-config."""

from __future__ import annotations

import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

CHECK = "select-and-batch-get-resource-config"
GROUP = 'resource-config'
SERVICES = ['config']

@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SelectResourceConfig rejects a malformed expression with InvalidExpressionException and answers a
    valid one; BatchGetResourceConfig silently omits unknown resource ids and unknown resource types
    from both result lists and never fabricates a configuration item."""
    cfg = ctx.client("config")
    # A malformed Select expression must be rejected, not silently return an
    # empty result set.
    code, message = _error(
        lambda: cfg.select_resource_config(Expression="SELECT ((( invalid")
    )
    assert code == "InvalidExpressionException", (
        f"a syntactically malformed Select expression must be refused with "
        f"InvalidExpressionException, not silently answered with an empty result "
        f"set; got {code!r}"
    )
    assert message == "syntax error at line 1, column 19", (
        f"expected the parser's exact position report, got {message!r}"
    )

    # A well-formed expression must succeed and return a (possibly empty)
    # Results list of JSON strings.
    resp = cfg.select_resource_config(
        Expression="SELECT resourceId WHERE resourceType = 'AWS::S3::Bucket'"
    )
    assert isinstance(resp["Results"], list), (
        f"a well-formed Select expression must succeed with a Results list, got "
        f"{resp!r}"
    )
    for row in resp["Results"]:
        json.loads(row)

    # An unknown-but-well-formed resource key is silently omitted: real AWS
    # returns BOTH lists empty rather than reporting it as unprocessed. It
    # must never fabricate a configuration item.
    missing_id = ctx.unique_name("sim2real-behav-cfg-absent-res-")
    batch = cfg.batch_get_resource_config(
        resourceKeys=[{"resourceType": "AWS::S3::Bucket", "resourceId": missing_id}]
    )
    assert batch["baseConfigurationItems"] == [], (
        f"a resource key that was never recorded must yield no configuration item "
        f"-- BatchGetResourceConfig must never fabricate one; got {batch!r}"
    )
    assert batch.get("unprocessedResourceKeys", []) == [], (
        f"a never-recorded key is omitted from BOTH lists, not reported as "
        f"unprocessed -- unprocessedResourceKeys is for keys Config could not "
        f"process, not for keys it simply has nothing on; got {batch!r}"
    )

    # Real AWS does NOT validate resourceType against the supported
    # enumeration here: an unknown type is accepted and simply matches
    # nothing -- the same silent-omission contract as an unknown resourceId,
    # not a ValidationException.
    unknown_type_batch = cfg.batch_get_resource_config(
        resourceKeys=[
            {"resourceType": "AWS::Nonexistent::Thing", "resourceId": missing_id}
        ]
    )
    assert unknown_type_batch["baseConfigurationItems"] == [], (
        f"an unmodelled resourceType must not be rejected -- it is accepted and "
        f"simply matches nothing; got {unknown_type_batch!r}"
    )
    assert unknown_type_batch.get("unprocessedResourceKeys", []) == [], (
        f"an unmodelled resourceType must be omitted the same way an unknown "
        f"resourceId is, not reported as unprocessed; got {unknown_type_batch!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
