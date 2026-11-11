"""list-tags-for-resource-nonexistent-resource-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-tags-for-resource-nonexistent-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["rtbfabric"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a well-formed but nonexistent gateway ARN answers
    InternalServerErrorException ("Internal server error."), not the documented
    ResourceNotFoundException.
    """
    rtb = ctx.client("rtbfabric")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_gateway_id = "rtb-gw-" + uuid.uuid4().hex[:18]
    resource_arn = f"arn:aws:rtbfabric:{ctx.region}:{account_id}:gateway/{fake_gateway_id}"

    error = _client_error(lambda: rtb.list_tags_for_resource(resourceArn=resource_arn))
    assert error["Code"] == "InternalServerErrorException", (
        f"expected InternalServerErrorException, got {error['Code']}"
    )
    expected_message = "Internal server error."
    assert error["Message"] == expected_message, f"expected {expected_message!r}, got {error['Message']!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (Code and Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must fail loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
