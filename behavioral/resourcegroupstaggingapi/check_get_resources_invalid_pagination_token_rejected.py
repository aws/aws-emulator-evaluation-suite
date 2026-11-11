"""get-resources-invalid-pagination-token-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-resources-invalid-pagination-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["resourcegroupstaggingapi"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A PaginationToken the service did not mint is refused with InvalidParameterException
    ("Pagination token is invalid=<token>") on GetResources and GetTagValues rather than read as
    page one, while a minted token advances the walk and the tagged set reads back unchanged.
    """
    sqs = ctx.client("sqs")
    rgt = ctx.client("resourcegroupstaggingapi")

    key = ctx.unique_name("sim2real-behav-token-")
    wanted = 3

    arns = []
    for _ in range(wanted):
        url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
        ctx.on_cleanup(lambda u=url: sqs.delete_queue(QueueUrl=u))
        arns.append(
            sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        )
    rgt.tag_resources(ResourceARNList=arns, Tags={key: "tokened"})
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=arns, TagKeys=[key]))

    _poll_until(
        lambda: {m["ResourceARN"] for m in _all_resources(rgt, TagFilters=[{"Key": key}])},
        lambda found: found == set(arns),
        timeout_s=180.0,
    )

    # Positive control: a token the service minted is accepted and advances the walk.
    first = rgt.get_resources(TagFilters=[{"Key": key}], ResourcesPerPage=1)
    real_token = first["PaginationToken"]
    assert real_token, (
        f"paging {wanted} resources one per page returned no PaginationToken on page one: "
        f"{first['ResourceTagMappingList']!r}"
    )
    second = rgt.get_resources(
        TagFilters=[{"Key": key}], ResourcesPerPage=1, PaginationToken=real_token
    )
    page_one = {m["ResourceARN"] for m in first["ResourceTagMappingList"]}
    page_two = {m["ResourceARN"] for m in second["ResourceTagMappingList"]}
    assert page_two and page_one != page_two, (
        f"a minted token did not advance the walk: page one {sorted(page_one)!r}, page two "
        f"{sorted(page_two)!r}"
    )

    # Break exactly one thing: a token the service never minted.
    bad_token = "sim2real-behav-not-a-real-token"
    code, message = _error_code_and_message(
        lambda: rgt.get_resources(TagFilters=[{"Key": key}], PaginationToken=bad_token)
    )
    assert code == "InvalidParameterException", (
        f"an unminted PaginationToken raised {code!r}, expected InvalidParameterException"
    )
    expected = f"Pagination token is invalid={bad_token}"
    assert message == expected, (
        f"an unminted PaginationToken was refused with {message!r}, expected {expected!r}"
    )

    # The refusal is total: the error is raised instead of a page, so no result is served with it.
    # The same corruption is refused on GetTagValues too, so it is the TOKEN that is validated
    # rather than one operation's argument list.
    code_values, message_values = _error_code_and_message(
        lambda: rgt.get_tag_values(Key=key, PaginationToken=bad_token)
    )
    assert code_values == "InvalidParameterException", (
        f"an unminted PaginationToken on GetTagValues raised {code_values!r}, expected "
        f"InvalidParameterException"
    )
    expected_values = f"Pagination token is invalid={bad_token}"
    assert message_values == expected_values, (
        f"an unminted PaginationToken on GetTagValues was refused with {message_values!r}, "
        f"expected {expected_values!r}"
    )

    # Effect absent: the refused walk served nothing, so the complete result set is still exactly
    # what this check tagged — a target that answered page one for the bad token would have left
    # the caller believing it had walked the set.
    assert {m["ResourceARN"] for m in _all_resources(rgt, TagFilters=[{"Key": key}])} == set(arns), (
        f"after the refusals the tag query for {key!r} no longer returns exactly the {wanted} "
        f"queues it tagged: {sorted(arns)!r}"
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
