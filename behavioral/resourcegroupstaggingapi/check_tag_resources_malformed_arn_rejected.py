"""tag-resources-malformed-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resources-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["resourcegroupstaggingapi"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """TagResources with a string that is not an ARN is refused for the whole request with
    InvalidParameterException ("<arn> is not a valid AmazonResourceName (ARN)") and tags nothing,
    not even the live queue in the batch; with a well-formed ARN the same call succeeds.
    """
    sqs = ctx.client("sqs")
    rgt = ctx.client("resourcegroupstaggingapi")

    bad_key = ctx.unique_name("sim2real-behav-badarn-")
    good_key = ctx.unique_name("sim2real-behav-goodarn-")

    q_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    live_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    # Break exactly one thing: a string that is not an ARN at all, alongside a live resource.
    not_an_arn = "sim2real-behav-not-an-arn"
    code, message = _error_code_and_message(
        lambda: rgt.tag_resources(ResourceARNList=[live_arn, not_an_arn], Tags={bad_key: "v"})
    )
    assert code == "InvalidParameterException", (
        f"tagging with a malformed ARN raised {code!r}, expected InvalidParameterException"
    )
    expected = f"{not_an_arn} is not a valid AmazonResourceName (ARN)"
    assert message == expected, (
        f"tagging with a malformed ARN was refused with {message!r}, expected {expected!r}"
    )

    # Effect absent, twice over: nothing carries the rejected key, and the live queue in the same
    # rejected batch was not tagged either.
    absent = _all_resources(rgt, TagFilters=[{"Key": bad_key}])
    assert absent == [], (
        f"the rejected key {bad_key!r} matched {[m['ResourceARN'] for m in absent]!r}; a request "
        f"rejected with InvalidParameterException must write nothing"
    )

    # Positive control in the same file: the same client, queue and shape succeed once the ARN is
    # well formed, so the rejection above is the malformed ARN and not a broken setup.
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
    # Re-read the rejected key AFTER the index has demonstrably converged on the control, so the
    # emptiness above cannot be an index that simply had not caught up.
    still_absent = _all_resources(rgt, TagFilters=[{"Key": bad_key}])
    assert still_absent == [], (
        f"the rejected key {bad_key!r} appeared in the index as "
        f"{[m['ResourceARN'] for m in still_absent]!r} after the control converged"
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


def _error_code_and_message(fn):
    """The error code and message from a call that MUST fail. An unexpected SUCCESS raises rather
    than returning a falsy sentinel: a target that ACCEPTS input real AWS refuses is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
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
