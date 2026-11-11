"""batch-get-aggregate-resource-config-malformed-batch-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-aggregate-resource-config-malformed-batch-rejected"
GROUP = "error-semantics"
SERVICES = ["config"]

_MAX_BATCH_SIZE = 100


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchGetAggregateResourceConfig with more than the documented 100 resource identifiers fails with
    ValidationException and its exact message (Java hash codes masked), while a batch of one undiscovered
    identifier succeeds with it unprocessed and no items."""
    config = ctx.client("config")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-config-aggr-")

    config.put_configuration_aggregator(
        ConfigurationAggregatorName=name,
        AccountAggregationSources=[
            {"AccountIds": [account_id], "AllAwsRegions": False, "AwsRegions": [ctx.region]}
        ],
        Tags=[{"Key": "sim2real", "Value": "batch-get-aggregate-resource-config-malformed-batch-rejected"}],
    )
    ctx.on_cleanup(lambda: config.delete_configuration_aggregator(ConfigurationAggregatorName=name))

    def identifier(i: int) -> dict:
        return {
            "SourceAccountId": account_id,
            "SourceRegion": ctx.region,
            "ResourceId": f"i-sim2real{i:016d}",
            "ResourceType": "AWS::EC2::Instance",
        }

    # Positive control: a well-formed batch at/under the max size succeeds (200),
    # even though none of these resources were ever discovered.
    ok_resp = config.batch_get_aggregate_resource_config(
        ConfigurationAggregatorName=name, ResourceIdentifiers=[identifier(0)]
    )
    unprocessed = ok_resp.get("UnprocessedResourceIdentifiers", [])
    assert len(unprocessed) == 1, (
        f"positive control: expected 1 unprocessed identifier, got {len(unprocessed)}: {unprocessed!r}"
    )
    items = ok_resp.get("BaseConfigurationItems", [])
    assert len(items) == 0, (
        f"positive control: expected 0 base configuration items for an undiscovered resource, got "
        f"{len(items)}: {items!r}"
    )

    # Break exactly one thing: exceed the maximum batch size of 100.
    oversized_batch = [identifier(i) for i in range(_MAX_BATCH_SIZE + 1)]
    code, message = _error(
        lambda: config.batch_get_aggregate_resource_config(
            ConfigurationAggregatorName=name, ResourceIdentifiers=oversized_batch
        )
    )
    assert code == "ValidationException", (
        f"a batch of {len(oversized_batch)} resource identifiers (max is {_MAX_BATCH_SIZE}) was "
        f"expected to be rejected with ValidationException, got {code!r}"
    )
    # The message echoes every identifier as a Java object hash code
    # (AggregateResourceIdentifier@<hash>), derived from the per-run account and ids; the
    # hashes are masked and the rest is exact.
    echoed = ", ".join(
        ["com.amazonaws.starling.dove.AggregateResourceIdentifier@<hash>"] * len(oversized_batch)
    )
    expected_message = (
        f"1 validation error detected: Value '[{echoed}]' at 'resourceIdentifiers' failed to "
        f"satisfy constraint: Member must have length less than or equal to {_MAX_BATCH_SIZE}"
    )
    masked = re.sub(r"@[0-9a-f]+\b", "@<hash>", message or "")
    assert masked == expected_message, (
        f"the refusal said {(message or '')[:300]!r}... ({len(message or '')} chars), expected "
        f"{expected_message[:300]!r}..."
    )


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
