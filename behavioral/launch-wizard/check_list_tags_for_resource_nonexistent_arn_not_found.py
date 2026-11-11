"""list-tags-for-resource-nonexistent-arn-not-found."""
from __future__ import annotations
import uuid

from behavioral_harness import tags

CHECK = "list-tags-for-resource-nonexistent-arn-not-found"
GROUP = "error-semantics"
SERVICES = ["launch-wizard"]


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a UUID-shaped but nonexistent deployment ARN raises NotFoundException "Resource
    was not found", a non-UUID deployment id raises BadRequestException "Invalid input resource arn", and
    ListWorkloads still succeeds."""
    lw = ctx.client("launch-wizard")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:launchwizard:{ctx.region}:{account_id}:deployment/{uuid.uuid4()}"

    code, message = _client_error(lambda: lw.list_tags_for_resource(resourceArn=bogus_arn))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "Resource was not found", f"got message={message!r}"

    # contrast: an ARN whose deployment id isn't UUID-shaped fails ARN parsing itself,
    # with a distinct (framework-level) error code, not the resource-lookup error above
    malformed_arn = f"arn:aws:launchwizard:{ctx.region}:{account_id}:deployment/sim2real0000000nosuch"
    malformed_code, malformed_message = _client_error(lambda: lw.list_tags_for_resource(resourceArn=malformed_arn))
    assert malformed_code == "BadRequestException", (
        f"expected BadRequestException for a non-UUID-shaped deployment id, got {malformed_code!r}"
    )
    assert malformed_message == "Invalid input resource arn", f"got message={malformed_message!r}"

    workloads = lw.list_workloads(maxResults=1)["workloads"]
    assert workloads, "expected the API channel itself to remain healthy: ListWorkloads returned no workloads"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
