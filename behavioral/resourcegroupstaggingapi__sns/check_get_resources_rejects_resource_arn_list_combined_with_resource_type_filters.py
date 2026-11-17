"""get-resources-rejects-resource-arn-list-combined-with-resource-type-filters."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resources-rejects-resource-arn-list-combined-with-resource-type-filters"
GROUP = "tag-inventory"
SERVICES = ["resourcegroupstaggingapi", "sns"]


def _resources_by_arn(rgta, arn: str, *, budget_s: float = 60.0, poll_s: float = 2.0) -> set:
    """ResourceARNs GetResources(ResourceARNList=[arn]) returns, polled until ``arn`` appears."""
    deadline = time.monotonic() + budget_s
    while True:
        found = {m["ResourceARN"]
                 for m in rgta.get_resources(ResourceARNList=[arn])["ResourceTagMappingList"]}
        if arn in found or time.monotonic() > deadline:
            return found
        time.sleep(poll_s)


def _error(fn) -> tuple[str, str]:
    """The ``(Error.Code, Error.Message)`` ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResources refuses ResourceARNList combined with ResourceTypeFilters in one call,
    and still answers ResourceARNList alone once the combination is removed.

    Reference: https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_GetResources.html
    """
    sns = ctx.client("sns")
    rgta = ctx.client("resourcegroupstaggingapi")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-rgta-arnlist-"),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    found = _resources_by_arn(rgta, topic_arn)
    assert topic_arn in found, (
        f"GetResources with ResourceARNList=[{topic_arn!r}] returned {sorted(found)!r}"
    )

    code, message = _error(lambda: rgta.get_resources(
        ResourceARNList=[topic_arn], ResourceTypeFilters=["sns:topic"],
    ))
    assert code == "InvalidParameterException", (
        f"combining ResourceARNList with ResourceTypeFilters gave {code!r}: {message!r}, "
        f"expected InvalidParameterException"
    )
    assert message == "ResourceTypeFilters is not allowed when providing a ResourceARNList.", (
        f"unexpected message for the combined-parameters refusal: {message!r}"
    )

    retry_found = _resources_by_arn(rgta, topic_arn)
    assert topic_arn in retry_found, (
        f"GetResources with ResourceARNList alone, retried after the refused combined call, "
        f"returned {sorted(retry_found)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
