"""tag-resource-nonexistent-connection-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-connection-rejected"
GROUP = "error-semantics"
SERVICES = ["interconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource against a same-account ARN whose Connection does not exist fails with InterconnectClientException."""
    ic = ctx.client("interconnect")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    # positive control: the client is otherwise healthy against this service, so the rejection
    # below can't be "every TagResource call fails" wearing a nonexistent-connection costume
    resp = ic.list_connections()
    assert "connections" in resp, f"got {resp!r}"

    arn = f"arn:aws:interconnect:{ctx.region}:{account}:connection/mcc-deadbeef"
    tag_code, tag_message = _error(lambda: ic.tag_resource(arn=arn, tags={"k": "v"}))
    assert tag_code == "InterconnectClientException", f"got {tag_code!r}"
    assert tag_message == "Unable to process request: Resource does not exist or is deleted", (
        f"got {tag_message!r}"
    )

    # effect absent: ListTagsForResource does not itself validate connection existence (a real
    # 200, not another rejection) -- the independent read must still show no tag was applied
    tags_seen = ic.list_tags_for_resource(arn=arn).get("tags", {})
    assert tags_seen == {}, f"got {tags_seen!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises; an accepted call fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
