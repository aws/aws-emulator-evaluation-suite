"""put-index-policy-limit-exceeded-fails."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-index-policy-limit-exceeded-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutIndexPolicy accepts a one-field policy but refuses a 300-field policy with
    InvalidParameterException and its exact message, and stores no policy.
    """
    logs = ctx.client("logs")

    log_group = ctx.unique_name("sim2real-behav-idxlimit-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    # Positive control: PutIndexPolicy's own Smithy documentation states the quota plainly --
    # "As many as 20 fields can be included in the policy" -- so a single-field policy must
    # succeed on this log group before the negative below is meaningful.
    small_policy = json.dumps({"FieldsV2": {"RequestId": {"type": "FIELD_INDEX"}}})
    put_resp = logs.put_index_policy(logGroupIdentifier=log_group, policyDocument=small_policy)
    assert put_resp["indexPolicy"]["policyDocument"] == small_policy
    described = logs.describe_index_policies(logGroupIdentifiers=[log_group])["indexPolicies"]
    assert len(described) == 1 and described[0]["policyDocument"] == small_policy, (
        f"expected the positive-control policy to be visible via DescribeIndexPolicies, got {described!r}"
    )
    logs.delete_index_policy(logGroupIdentifier=log_group)

    # PutIndexPolicy's policyDocument uses the "FieldsV2" schema (a map of field name -> {"type":
    # ...}). Use short field names so the document stays comfortably under the documented 51200 byte
    # size limit, while the number of fields (300) is more than an order of magnitude past the
    # documented 20-field-per-policy quota, to reliably trip the field-count limit specifically.
    #
    # On real AWS, exceeding the per-policy field-count quota is reported the same way as an
    # oversized policyDocument: as a malformed/invalid *parameter* (InvalidParameterException),
    # not as a resource-count quota violation (LimitExceededException).
    too_many_fields = {"FieldsV2": {f"Field{i:05d}": {"type": "FIELD_INDEX"} for i in range(300)}}
    policy_document = json.dumps(too_many_fields)
    assert len(policy_document.encode("utf-8")) < 51200
    code, msg = _error(
        lambda: logs.put_index_policy(
            logGroupIdentifier=log_group, policyDocument=policy_document
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a 300-field index policy (the documented quota "
        f"is 20 fields per policy), got {code!r}"
    )
    assert msg == "Policy document contains more than 20 fields.", f"got {msg!r}"

    # No partial/invalid policy should have been persisted by the rejected call.
    described_after = logs.describe_index_policies(logGroupIdentifiers=[log_group])["indexPolicies"]
    assert described_after == [], (
        f"a policy exceeding the field quota should never have been stored: {described_after!r}"
    )


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a mere mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
