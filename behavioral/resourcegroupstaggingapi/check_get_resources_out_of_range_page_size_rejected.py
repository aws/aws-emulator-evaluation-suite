"""get-resources-out-of-range-page-size-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-resources-out-of-range-page-size-rejected"
GROUP = "overly-permissive"
SERVICES = ["resourcegroupstaggingapi"]

# The service's own documented window for ResourcesPerPage. A fixed API constant, not an
# account quota: AWS does not raise this for one account, so reading it as a constant is safe.
_MIN_PER_PAGE = 1
_MAX_PER_PAGE = 100


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """GetResources refuses ResourcesPerPage 0 and 101 with InvalidParameterException and accepts
    both edges, 1 and 100: an exactly full page still returns a token whose page is empty and ends
    the walk, an under-full page ends it at once.
    """
    sqs = ctx.client("sqs")
    rgt = ctx.client("resourcegroupstaggingapi")

    key = ctx.unique_name("sim2real-behav-perpage-")

    q_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    rgt.tag_resources(ResourceARNList=[q_arn], Tags={key: "sized"})
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=[q_arn], TagKeys=[key]))

    settled = _poll_until(
        lambda: {m["ResourceARN"] for m in _all_resources(rgt, TagFilters=[{"Key": key}])},
        lambda arns: arns == {q_arn},
        timeout_s=180.0,
    )
    assert settled == {q_arn}, (
        f"the tagged queue never reached the index under {key!r}: saw {sorted(settled)!r}"
    )

    expected_message = (
        f"ResourcesPerPage is not in the valid range of {_MIN_PER_PAGE} and {_MAX_PER_PAGE}"
    )

    below, below_message = _error_code_and_message(
        lambda: rgt.get_resources(TagFilters=[{"Key": key}], ResourcesPerPage=_MIN_PER_PAGE - 1)
    )
    assert below == "InvalidParameterException", (
        f"ResourcesPerPage={_MIN_PER_PAGE - 1} raised {below!r}, expected InvalidParameterException"
    )
    assert below_message == expected_message, (
        f"ResourcesPerPage={_MIN_PER_PAGE - 1} was refused with {below_message!r}, expected "
        f"{expected_message!r}"
    )

    above, above_message = _error_code_and_message(
        lambda: rgt.get_resources(TagFilters=[{"Key": key}], ResourcesPerPage=_MAX_PER_PAGE + 1)
    )
    assert above == "InvalidParameterException", (
        f"ResourcesPerPage={_MAX_PER_PAGE + 1} raised {above!r}, expected InvalidParameterException"
    )
    assert above_message == expected_message, (
        f"ResourcesPerPage={_MAX_PER_PAGE + 1} was refused with {above_message!r}, expected "
        f"{expected_message!r}"
    )

    # Positive control at BOTH edges of the window, so the refusals above are the range and not
    # the parameter being unsupported.
    for size in (_MIN_PER_PAGE, _MAX_PER_PAGE):
        page = rgt.get_resources(TagFilters=[{"Key": key}], ResourcesPerPage=size)
        arns = {m["ResourceARN"] for m in page["ResourceTagMappingList"]}
        assert arns == {q_arn}, (
            f"ResourcesPerPage={size} returned {sorted(arns)!r}, expected exactly {q_arn!r}"
        )

    # The two accepted edges terminate DIFFERENTLY over the same one-resource set, and the
    # difference is a measured property of this service rather than of the request: an EXACTLY
    # FULL page (1 of 1) still carries a continuation token, and only following it reveals the
    # empty final page, while an under-full page (1 of 100) ends the walk immediately.
    full = rgt.get_resources(TagFilters=[{"Key": key}], ResourcesPerPage=_MIN_PER_PAGE)
    assert full["PaginationToken"], (
        f"an exactly-full page (ResourcesPerPage={_MIN_PER_PAGE} over 1 resource) ended the walk "
        f"with an empty token; real AWS returns a continuation token here"
    )
    tail = rgt.get_resources(
        TagFilters=[{"Key": key}],
        ResourcesPerPage=_MIN_PER_PAGE,
        PaginationToken=full["PaginationToken"],
    )
    assert tail["ResourceTagMappingList"] == [], (
        f"following the continuation token past the last resource returned "
        f"{[m['ResourceARN'] for m in tail['ResourceTagMappingList']]!r}, expected an empty page"
    )
    assert tail["PaginationToken"] == "", (
        f"the empty final page carried another token {tail['PaginationToken']!r}, which would not "
        f"terminate the walk"
    )

    under_full = rgt.get_resources(TagFilters=[{"Key": key}], ResourcesPerPage=_MAX_PER_PAGE)
    assert under_full["PaginationToken"] == "", (
        f"an under-full page (ResourcesPerPage={_MAX_PER_PAGE} over 1 resource) returned a "
        f"continuation token {under_full['PaginationToken']!r}, expected the empty string"
    )

    # Effect absent: a refused query changed nothing about the index it queried.
    after = {m["ResourceARN"] for m in _all_resources(rgt, TagFilters=[{"Key": key}])}
    assert after == {q_arn}, (
        f"after the refused queries the tag filter {key!r} matched {sorted(after)!r}, expected "
        f"exactly {q_arn!r}"
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
