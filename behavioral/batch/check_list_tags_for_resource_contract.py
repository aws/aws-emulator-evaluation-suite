"""list-tags-for-resource-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-resource-contract"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource returns exactly the tags on a resource and rejects an unknown ARN."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")

    arn = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={"computeReservation": 0, "shareDecaySeconds": 0, "shareDistribution": []},
        tags={"team": "sim2real", "purpose": "behavioral-check"},
    )["arn"]
    ctx.on_cleanup(lambda: _best_effort_delete(batch, arn))

    tags = batch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"team": "sim2real", "purpose": "behavioral-check"}, tags

    # Tags mutate live and are immediately visible through ListTagsForResource.
    batch.tag_resource(resourceArn=arn, tags={"stage": "extra"})
    updated_tags = batch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert updated_tags == {"team": "sim2real", "purpose": "behavioral-check", "stage": "extra"}, updated_tags

    batch.untag_resource(resourceArn=arn, tagKeys=["purpose"])
    final_tags = batch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert final_tags == {"team": "sim2real", "stage": "extra"}, final_tags

    # Negative: a malformed resource ARN (not matching the ARN format at all) is rejected. Real
    # Batch's REST front end rejects a resourceArn that doesn't even parse as an ARN at the
    # request-framework level, surfacing the generic "BadRequestException" rather than the
    # operation-specific ClientException/ServerException pair declared in the service model.
    bogus_arn = "not-a-valid-arn"
    code, message = _error_code(lambda: batch.list_tags_for_resource(resourceArn=bogus_arn))
    assert code == "BadRequestException", f"expected BadRequestException for malformed ARN, got {code}"
    assert message == "Invalid input resource arn: bad syntax", f"unexpected message {message!r}"

    # The real resource's tags are unaffected by the rejected lookup.
    still_final = batch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert still_final == final_tags, f"expected unaffected {final_tags}, got {still_final}"


def _error_code(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _best_effort_delete(batch, arn: str) -> None:
    batch.delete_scheduling_policy(arn=arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
