"""tag-resources-cross-region-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resources-cross-region-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["resourcegroupstaggingapi"]

# Two well-known long-lived commercial regions; the check picks whichever one is NOT the region it
# is running in, so the request is cross-region wherever it runs and no region is hardcoded as the
# target. Only the ARN's region field is wrong — the queue it names is never created anywhere.
_REGION_CANDIDATES = ("us-east-1", "us-west-2")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """TagResources with an ARN from another region is refused for the whole request with
    InvalidParameterException and leaves the same-region queue in the batch untagged; the same batch
    without the foreign ARN succeeds and the queue is indexed.
    """
    sqs = ctx.client("sqs")
    rgt = ctx.client("resourcegroupstaggingapi")
    sts = ctx.client("sts")

    account = sts.get_caller_identity()["Account"]
    foreign_region = next(r for r in _REGION_CANDIDATES if r != ctx.region)
    assert foreign_region != ctx.region, (
        f"could not pick a region other than {ctx.region!r} from {_REGION_CANDIDATES!r}"
    )

    bad_key = ctx.unique_name("sim2real-behav-xregion-")
    good_key = ctx.unique_name("sim2real-behav-inregion-")

    q_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    live_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    foreign_arn = f"arn:aws:sqs:{foreign_region}:{account}:{ctx.unique_name('sim2real-behav-far-')}"

    code, message = _error(
        lambda: rgt.tag_resources(ResourceARNList=[live_arn, foreign_arn], Tags={bad_key: "v"})
    )
    assert code == "InvalidParameterException", (
        f"tagging an ARN in {foreign_region!r} from the {ctx.region!r} endpoint raised {code!r}, "
        f"expected InvalidParameterException"
    )
    expected_message = (
        f"Region in the ARN {foreign_arn} does not match with the region in which "
        "TagResources API is invoked"
    )
    assert message == expected_message, (
        f"the cross-region refusal message was {message!r}, expected {expected_message!r}"
    )

    # Effect absent: the rejected batch wrote nothing, including for the same-region ARN in it.
    leaked = _all_resources(rgt, TagFilters=[{"Key": bad_key}])
    assert leaked == [], (
        f"the rejected key {bad_key!r} matched {[m['ResourceARN'] for m in leaked]!r}; a "
        f"cross-region rejection must leave the whole batch unwritten"
    )

    # Positive control: drop the foreign ARN and nothing else, and the same call succeeds.
    ok = rgt.tag_resources(ResourceARNList=[live_arn], Tags={good_key: "v"})
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=[live_arn], TagKeys=[good_key]))
    assert ok["FailedResourcesMap"] == {}, (
        f"the positive control reported per-resource failures: {ok['FailedResourcesMap']!r}"
    )
    found = _poll_until(
        lambda: {m["ResourceARN"] for m in _all_resources(rgt, TagFilters=[{"Key": good_key}])},
        lambda arns: arns == {live_arn},
        timeout_s=180.0,
    )
    assert found == {live_arn}, (
        f"the positive control's tag filter {good_key!r} matched {sorted(found)!r}, expected exactly "
        f"{live_arn!r}"
    )
    still_absent = _all_resources(rgt, TagFilters=[{"Key": bad_key}])
    assert still_absent == [], (
        f"the rejected key {bad_key!r} appeared as {[m['ResourceARN'] for m in still_absent]!r} "
        f"after the control converged"
    )


def _all_resources(rgt, **kwargs):
    """Every ResourceTagMapping for a GetResources query, following PaginationToken to the end."""
    out, token = [], ""
    while True:
        page = rgt.get_resources(**kwargs, **({"PaginationToken": token} if token else {}))
        out.extend(page["ResourceTagMappingList"])
        token = page["PaginationToken"]
        if not token:
            return out


def _error(fn):
    """The error code from a call that MUST fail. An unexpected SUCCESS raises rather than returning
    a falsy sentinel: a target that ACCEPTS input real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
