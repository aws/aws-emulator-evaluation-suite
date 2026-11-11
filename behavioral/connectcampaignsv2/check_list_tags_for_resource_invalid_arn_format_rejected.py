"""list-tags-for-resource-invalid-arn-format-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-invalid-arn-format-rejected"
GROUP = "error-semantics"
SERVICES = ["connectcampaignsv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource answers a well-formed unknown campaign ARN with NotFoundException "Resource was
    not found", and an ARN with an unrecognized resource path with BadRequestException "Invalid input
    resource arn": path parsing fails before any existence lookup."""
    campaigns = ctx.client("connectcampaignsv2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Control: same account/partition/region and a recognized `campaign/<uuid>` shape, but no
    # such campaign was ever created. This must clear shape parsing and fail only the existence
    # check, proving the operation is otherwise reachable and NotFoundException is available as
    # a distinct outcome from BadRequestException.
    control_arn = f"arn:aws:connect-campaigns:{ctx.region}:{account_id}:campaign/{uuid.uuid4()}"

    def _list_tags_control():
        campaigns.list_tags_for_resource(arn=control_arn)

    control = _error(_list_tags_control)
    assert control["Code"] == "NotFoundException", (
        f"expected NotFoundException for well-formed nonexistent arn, got {control['Code']}"
    )
    assert control["Message"] == "Resource was not found", (
        f"expected message 'Resource was not found', got {control['Message']!r}"
    )

    # Same account/partition/region as the caller (so this isn't a cross-account-access
    # rejection), but the resource path is not a recognized connect-campaigns resource type.
    bad_arn = f"arn:aws:connect-campaigns:{ctx.region}:{account_id}:not-a-real-resource-path"

    def _list_tags():
        campaigns.list_tags_for_resource(arn=bad_arn)

    err = _error(_list_tags)
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err['Code']}"
    assert err["Message"] == "Invalid input resource arn", (
        f"expected message 'Invalid input resource arn', got {err['Message']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
