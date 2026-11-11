"""op-contract-untag-resource."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "op-contract-untag-resource"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the named tag keys and leaves others intact;
    UntagResource on a syntactically valid but nonexistent resourceArn is rejected
    with NotFoundException and mutates nothing."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    created = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={"computeReservation": 10, "shareDecaySeconds": 600},
        tags={"env": "behav", "team": "batch"},
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: batch.delete_scheduling_policy(arn=arn))

    tags_before = batch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_before == {"env": "behav", "team": "batch"}, f"expected {{'env': 'behav', 'team': 'batch'}}, got {tags_before}"

    # success path: untag exactly one key
    batch.untag_resource(resourceArn=arn, tagKeys=["env"])
    tags_after = batch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after == {"team": "batch"}, f"expected {{'team': 'batch'}}, got {tags_after}"

    # error boundary: resourceArn syntactically valid but not present
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:batch:{ctx.region}:{account_id}:scheduling-policy/{ctx.unique_name('sim2real-batch-sp-missing-')}"
    code, message = _error_code(lambda: batch.untag_resource(resourceArn=bogus_arn, tagKeys=["team"]))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "Resource was not found", f"unexpected message {message!r}"

    # the real resource's tags were not touched by the failed call against a different arn
    tags_final = batch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_final == {"team": "batch"}, f"expected {{'team': 'batch'}}, got {tags_final}"


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
