"""list-tags-for-resource-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["pcs"]


_NOT_FOUND_MESSAGE = "Resource cannot be found."


def _not_found_detail(e: ClientError) -> tuple[str, str]:
    err = e.response["Error"]
    code = err["Code"]
    message = err.get("Message", "")
    return code, message


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource, TagResource and UntagResource on a well-formed ARN for a nonexistent cluster
    each get ResourceNotFoundException with the exact not-found message, while ListClusters succeeds for
    the same caller."""
    pcs = ctx.client("pcs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_arn = (
        f"arn:aws:pcs:{ctx.region}:{account_id}:cluster/pcs_"
        + ctx.unique_name("nonexist").lower().replace("-", "").replace("_", "")
    )

    code = message = None
    try:
        pcs.list_tags_for_resource(resourceArn=bogus_arn)
    except ClientError as e:
        code, message = _not_found_detail(e)

    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == _NOT_FOUND_MESSAGE, f"expected message {_NOT_FOUND_MESSAGE!r}, got {message!r}"

    # Positive control: a plain list call against the same account/region still succeeds,
    # so the rejections below cannot be explained by a broken client or blanket denial.
    resp = pcs.list_clusters(maxResults=1)
    assert isinstance(resp.get("clusters"), list), "positive control ListClusters did not return a list"

    # TagResource against the same nonexistent ARN is rejected the same
    # deterministic way (no tags silently persisted anywhere).
    tag_code = tag_message = None
    try:
        pcs.tag_resource(resourceArn=bogus_arn, tags={"k": "v"})
    except ClientError as e:
        tag_code, tag_message = _not_found_detail(e)
    assert tag_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {tag_code}"
    assert tag_message == _NOT_FOUND_MESSAGE, (
        f"expected message {_NOT_FOUND_MESSAGE!r}, got {tag_message!r}"
    )

    untag_code = untag_message = None
    try:
        pcs.untag_resource(resourceArn=bogus_arn, tagKeys=["k"])
    except ClientError as e:
        untag_code, untag_message = _not_found_detail(e)
    assert untag_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {untag_code}"
    assert untag_message == _NOT_FOUND_MESSAGE, (
        f"expected message {_NOT_FOUND_MESSAGE!r}, got {untag_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
