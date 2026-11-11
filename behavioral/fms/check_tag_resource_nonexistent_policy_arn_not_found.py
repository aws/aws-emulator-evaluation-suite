"""tag-resource-nonexistent-policy-arn-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-policy-arn-not-found"
GROUP = "not-found"
SERVICES = ["fms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource raises ResourceNotFoundException for a syntactically well-formed
    Firewall Manager policy ARN that does not correspond to an existing policy, and
    does not create any tag state as a side effect.
    """
    fms = ctx.client("fms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    fake_arn = f"arn:aws:fms:{ctx.region}:{account_id}:policy/{uuid.uuid4()}"
    code, message = _error_code(
        lambda: fms.tag_resource(ResourceArn=fake_arn, TagList=[{"Key": "k", "Value": "v"}])
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "The referenced item does not exist.", f"unexpected message: {message!r}"

    # no side effect: listing tags for the same nonexistent arn still fails not-found,
    # never returns the tag we attempted to attach
    list_code, list_message = _error_code(lambda: fms.list_tags_for_resource(ResourceArn=fake_arn))
    assert list_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {list_code}"
    assert list_message == "The referenced item does not exist.", f"unexpected message: {list_message!r}"


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
