"""tag-resource-nonexistent-arn-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-arn-not-found"
GROUP = "error-semantics"
SERVICES = ["connectcampaignsv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource on a well-formed ARN of a campaign that never existed fails with NotFoundException
    "Resource was not found", and ListTagsForResource on the same ARN answers the same, so no tag persists."""
    campaigns = ctx.client("connectcampaignsv2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = (
        f"arn:aws:connect-campaigns:{ctx.region}:{account_id}:campaign/{uuid.uuid4()}"
    )

    def _tag():
        return campaigns.tag_resource(arn=fake_arn, tags={"owner": "sim2real"})

    err = _error(_tag)
    assert err["Code"] == "NotFoundException", f"expected NotFoundException, got {err['Code']}"
    assert err["Message"] == "Resource was not found", (
        f"expected message 'Resource was not found', got {err['Message']!r}"
    )

    def _list_tags():
        return campaigns.list_tags_for_resource(arn=fake_arn)

    err2 = _error(_list_tags)
    assert err2["Code"] == "NotFoundException", f"expected NotFoundException, got {err2['Code']}"
    assert err2["Message"] == "Resource was not found", (
        f"expected message 'Resource was not found', got {err2['Message']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
