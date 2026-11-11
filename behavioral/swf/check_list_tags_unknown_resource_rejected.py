"""list-tags-unknown-resource-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-unknown-resource-rejected"
GROUP = "negative-classes"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource for a domain ARN that does not refer to an existing domain fails with UnknownResourceFault."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    real_arn = swf.describe_domain(name=domain)["domainInfo"]["arn"]

    nonexistent_domain = ctx.unique_name("sim2real-swf-missing-")
    fake_arn = real_arn.rsplit("/", 1)[0] + "/" + nonexistent_domain
    assert fake_arn != real_arn, (
        f"generated fake_arn {fake_arn!r} collided with the real domain's own ARN {real_arn!r}"
    )

    code, message = _error(lambda: swf.list_tags_for_resource(resourceArn=fake_arn))
    assert code == "UnknownResourceFault", (
        f"ListTagsForResource on nonexistent domain ARN {fake_arn!r} returned error code "
        f"{code!r}, expected UnknownResourceFault"
    )
    expected = f"Unknown domain: {nonexistent_domain}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # corroborate: the domain the fake ARN points at genuinely does not exist
    describe_code, describe_message = _error(lambda: swf.describe_domain(name=nonexistent_domain))
    assert describe_code == "UnknownResourceFault", (
        f"DescribeDomain on nonexistent domain {nonexistent_domain!r} returned error code "
        f"{describe_code!r}, expected UnknownResourceFault"
    )
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"

    # positive control: the real domain's ARN lists the tag the domain is registered with
    tags = swf.list_tags_for_resource(resourceArn=real_arn)["tags"]
    expected_tag = {"key": "sim2real:infra", "value": "swf-shared"}
    assert expected_tag in tags, (
        f"ListTagsForResource on the real domain's ARN {real_arn!r} returned {tags!r}, "
        f"expected it to hold {expected_tag!r}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


_SHARED_DOMAIN = "sim2real-swf-shared"


def _shared_domain(ctx) -> str:
    """The account's shared SWF domain, registered if absent and never deprecated: SWF has no
    DeleteDomain, and a deprecated domain counts toward the registered-domain quota."""
    swf = ctx.client("swf")
    try:
        status = swf.describe_domain(name=_SHARED_DOMAIN)["domainInfo"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise
        status = None
    try:
        if status is None:
            swf.register_domain(
                name=_SHARED_DOMAIN,
                workflowExecutionRetentionPeriodInDays="1",
                tags=[{"key": "sim2real:infra", "value": "swf-shared"}],
            )
        elif status == "DEPRECATED":
            swf.undeprecate_domain(name=_SHARED_DOMAIN)
    except ClientError as exc:
        # A concurrent run registered or restored it first.
        if exc.response["Error"]["Code"] != "DomainAlreadyExistsFault":
            raise
    return _SHARED_DOMAIN


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
