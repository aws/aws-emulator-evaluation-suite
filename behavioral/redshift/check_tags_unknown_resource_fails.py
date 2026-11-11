"""tags-unknown-resource-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _error(fn):
    """Call *fn* and return the (code, message) of the AWS error it raises; a success fails."""
    try:
        _retrying(fn)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("the call succeeded where AWS rejects it")


def _delete_absent_ok(delete, gone_code):
    """Teardown: the parameter group delete is synchronous; one that was never created answers *gone_code*."""
    try:
        delete()
    except ClientError as exc:
        if _code_of(exc) != gone_code:
            raise


CHECK = "tags-unknown-resource-fails"
GROUP = 'error-semantics'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTags on a cluster ARN with no backing resource fails with ResourceNotFoundFault and its
    exact message and leaves other tags untouched, while CreateTags on a real resource succeeds."""
    rs = ctx.client("redshift")
    account = ctx.client("sts").get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-behav-rs-notag-pg-")
    ctx.on_cleanup(lambda: _delete_absent_ok(
        lambda: rs.delete_cluster_parameter_group(ParameterGroupName=group_name), "ClusterParameterGroupNotFound"
    ))
    rs.create_cluster_parameter_group(
        ParameterGroupName=group_name,
        ParameterGroupFamily="redshift-1.0",
        Description="sim2real positive control for tags-unknown-resource-fails",
    )
    real_arn = f"arn:aws:redshift:{ctx.region}:{account}:parametergroup:{group_name}"

    # Positive control: CreateTags succeeds against a real resource.
    rs.create_tags(ResourceName=real_arn, Tags=[{"Key": "sim2real-behav", "Value": "true"}])
    tagged = {
        t["Tag"]["Key"]: t["Tag"]["Value"]
        for t in rs.describe_tags(ResourceName=real_arn)["TaggedResources"]
    }
    assert tagged == {"sim2real-behav": "true"}, f"positive control failed to tag, got {tagged}"

    bogus_cluster = ctx.unique_name("sim2real-behav-rs-notag-")
    bogus_arn = f"arn:aws:redshift:{ctx.region}:{account}:cluster:{bogus_cluster}"
    code, message = _error(lambda: rs.create_tags(
        ResourceName=bogus_arn, Tags=[{"Key": "k", "Value": "v"}]
    ))
    assert code == "ResourceNotFoundFault", f"expected ResourceNotFoundFault, got {code}"
    assert message == f"cluster ({bogus_cluster}) was not found.", message

    # Effect absent: the real resource's tags are untouched by the failed call.
    tagged_after = {
        t["Tag"]["Key"]: t["Tag"]["Value"]
        for t in rs.describe_tags(ResourceName=real_arn)["TaggedResources"]
    }
    assert tagged_after == {"sim2real-behav": "true"}, (
        f"unrelated resource's tags changed after the rejected call, got {tagged_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
