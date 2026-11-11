"""tag-resources-system-tag-prefix-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resources-system-tag-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["resourcegroupstaggingapi"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """TagResources with a key in the reserved `aws:` namespace is refused with
    InvalidParameterException ("The caller isn't allowed to modify system tags") and never enters the
    index, while the same key without the prefix is accepted and the queue carries only that key.
    """
    sqs = ctx.client("sqs")
    rgt = ctx.client("resourcegroupstaggingapi")

    suffix = ctx.unique_name("sim2real-behav-sys-").rsplit("-", 1)[-1]
    reserved_key = f"aws:sim2real-behav-{suffix}"
    customer_key = f"sim2real-behav-{suffix}"

    q_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    live_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    code, message = _error_code_and_message(
        lambda: rgt.tag_resources(ResourceARNList=[live_arn], Tags={reserved_key: "v"})
    )
    assert code == "InvalidParameterException", (
        f"writing the reserved key {reserved_key!r} raised {code!r}, expected InvalidParameterException"
    )
    expected = "The caller isn't allowed to modify system tags."
    assert message == expected, (
        f"writing the reserved key {reserved_key!r} was refused with {message!r}, expected "
        f"{expected!r}"
    )

    # Effect absent: the reserved key is nowhere in the index.
    leaked = _all_resources(rgt, TagFilters=[{"Key": reserved_key}])
    assert leaked == [], (
        f"the reserved key {reserved_key!r} matched {[m['ResourceARN'] for m in leaked]!r}; the "
        f"refusal must leave nothing behind"
    )

    # Positive control: the SAME name without the reserved prefix is accepted, so the refusal is
    # the `aws:` namespace and not the key's spelling, the queue or the client.
    ok = rgt.tag_resources(ResourceARNList=[live_arn], Tags={customer_key: "v"})
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=[live_arn], TagKeys=[customer_key]))
    assert ok["FailedResourcesMap"] == {}, (
        f"the positive control reported per-resource failures: {ok['FailedResourcesMap']!r}"
    )
    found = _poll_until(
        lambda: {m["ResourceARN"] for m in _all_resources(rgt, TagFilters=[{"Key": customer_key}])},
        lambda arns: arns == {live_arn},
        timeout_s=180.0,
    )
    assert found == {live_arn}, (
        f"the positive control's tag filter {customer_key!r} matched {sorted(found)!r}, expected "
        f"exactly {live_arn!r}"
    )

    # And the queue's own tag set, read back through the index, carries only the customer key.
    mapping = _all_resources(rgt, TagFilters=[{"Key": customer_key}])
    pairs = {t["Key"]: t["Value"] for t in mapping[0]["Tags"]}
    assert reserved_key not in pairs, (
        f"the queue's indexed tags are {pairs!r}, which includes the rejected reserved key"
    )
    assert pairs.get(customer_key) == "v", (
        f"the queue's indexed tags are {pairs!r}, which does not carry {customer_key}=v"
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
