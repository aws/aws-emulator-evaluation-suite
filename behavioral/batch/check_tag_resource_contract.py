"""tag-resource-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-contract"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags that are immediately visible on the resource, and rejects an unknown ARN."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-cr-")

    arn = batch.create_consumable_resource(
        consumableResourceName=name,
        totalQuantity=5,
        resourceType="REPLENISHABLE",
    )["consumableResourceArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(batch, arn))

    described_before = batch.describe_consumable_resource(consumableResource=arn)
    assert described_before.get("tags", {}) == {}, described_before.get("tags")

    batch.tag_resource(resourceArn=arn, tags={"owner": "sim2real-behav", "tier": "1"})

    described_after = batch.describe_consumable_resource(consumableResource=arn)
    assert described_after["tags"] == {"owner": "sim2real-behav", "tier": "1"}, described_after["tags"]
    from_list = batch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert from_list == {"owner": "sim2real-behav", "tier": "1"}, from_list

    # Adding a second tag call merges with the existing tags rather than replacing them.
    batch.tag_resource(resourceArn=arn, tags={"tier": "2", "extra": "yes"})
    merged = batch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert merged == {"owner": "sim2real-behav", "tier": "2", "extra": "yes"}, merged

    # Negative: a malformed resource ARN (not matching the ARN format at all) is rejected. Real
    # Batch's REST front end rejects a resourceArn that doesn't even parse as an ARN at the
    # request-framework level, surfacing the generic "BadRequestException" rather than the
    # operation-specific ClientException/ServerException pair declared in the service model.
    bogus_arn = "not-a-valid-arn"
    code, message = _client_error(lambda: batch.tag_resource(resourceArn=bogus_arn, tags={"x": "y"}))
    assert code == "BadRequestException", f"expected BadRequestException for malformed ARN, got {code}"
    expected_message = "Invalid input resource arn: bad syntax"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The real resource's tags are unaffected by the rejected call against the bogus ARN.
    still_merged = batch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert still_merged == merged, (still_merged, merged)


def _client_error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete(batch, arn: str) -> None:
    batch.delete_consumable_resource(consumableResource=arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
