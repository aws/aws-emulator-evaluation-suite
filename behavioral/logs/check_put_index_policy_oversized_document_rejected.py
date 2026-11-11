"""put-index-policy-oversized-document-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-index-policy-oversized-document-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIndexPolicy rejects an oversized policyDocument (well past the
    documented 51200 byte size limit) with LimitExceededException, rather
    than silently truncating or accepting it."""
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-idxsz-")
    logs.create_log_group(logGroupName=log_group_name, logGroupClass="STANDARD")
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    # Build a policy document using the "FieldsV2" schema (a map of field name -> {"type": ...}),
    # which is the schema that PutIndexPolicy actually accepts. The flat "Fields" list of plain
    # strings is not a recognized policyDocument shape, so sending it (regardless of size) gets
    # rejected for being malformed before any size limit is ever evaluated. Pad the map with enough
    # entries to push the document comfortably past the documented 51200 byte limit.
    huge_fields = {f"Field{i:05d}": {"type": "FIELD_INDEX"} for i in range(3000)}
    oversized_policy = json.dumps({"FieldsV2": huge_fields})
    assert len(oversized_policy.encode("utf-8")) > 51200

    # An oversized policyDocument is rejected before it is evaluated as a set
    # of field-index entries, so real AWS reports it as a malformed/oversized
    # *parameter* (InvalidParameterException) rather than as having exceeded
    # a resource-count quota (LimitExceededException).
    code, msg = _error(
        lambda: logs.put_index_policy(
            logGroupIdentifier=log_group_name, policyDocument=oversized_policy
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for an oversized "
        f"index policy document, got {code!r}"
    )
    assert msg == (
        "1 validation error detected: Value at 'policyDocument' failed to satisfy constraint: "
        "Member must have length less than or equal to 51200"
    ), f"got {msg!r}"

    # A well-formed, reasonably sized policy on the same log group must still
    # succeed afterwards -- the rejection must not have left the log group in
    # a broken state.
    small_policy = json.dumps({"FieldsV2": {"RequestId": {"type": "FIELD_INDEX"}}})
    put_resp = logs.put_index_policy(logGroupIdentifier=log_group_name, policyDocument=small_policy)
    assert put_resp["indexPolicy"]["policyDocument"] == small_policy

    # Independent read through a different operation (DescribeIndexPolicies)
    # than the one that mutated: the earlier rejection must not have left the
    # log group unable to actually store a subsequent, well-formed policy.
    described = logs.describe_index_policies(logGroupIdentifiers=[log_group_name])
    assert described["indexPolicies"][0]["policyDocument"] == small_policy, (
        f"expected DescribeIndexPolicies to reflect the small policy, got {described!r}"
    )

    # The delete is otherwise unasserted -- prove it actually took effect via
    # an independent read, and that a second delete on the now-absent policy
    # fails with the specific not-found error.
    logs.delete_index_policy(logGroupIdentifier=log_group_name)
    described_after = logs.describe_index_policies(logGroupIdentifiers=[log_group_name])
    assert described_after.get("indexPolicies", []) == [], (
        f"expected no index policy after delete, got {described_after!r}"
    )
    delete_code, delete_msg = _error(
        lambda: logs.delete_index_policy(logGroupIdentifier=log_group_name)
    )
    assert delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted index "
        f"policy, got {delete_code!r}"
    )
    assert delete_msg == "Specified resource does not exist!", f"got {delete_msg!r}"


def _error(fn):
    """Call fn(); return its (error code, error message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
