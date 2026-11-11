"""tag-connection-preferences-round-trip."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-connection-preferences-round-trip"
GROUP = "tagging"
SERVICES = ["partnercentral-account"]


def _pca_client(ctx):
    """partnercentral-account is served only from us-east-1. ``region=`` pins that region while
    ctx.client keeps the caller's credentials and endpoint wiring; an emulator serves every
    region on one endpoint, so the same call is correct there."""
    return ctx.client("partnercentral-account", region="us-east-1")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetConnectionPreferences returns an Arn with an empty account-id segment for the "AWS" and "Sandbox"
    catalogs, and TagResource, ListTagsForResource and UntagResource all reject that ARN, whose shape their
    ResourceArn pattern does not allow.
    """
    pca = _pca_client(ctx)

    # Positive control: the account and credentials are otherwise healthy for this service.
    resp = pca.get_connection_preferences(Catalog="AWS")
    arn = resp["Arn"]
    assert arn, "expected GetConnectionPreferences to return a positive-control Arn, got none"

    key = "sim2real-pca-" + uuid.uuid4().hex[:8]

    for op_name, call in (
        ("TagResource", lambda: pca.tag_resource(ResourceArn=arn, Tags=[{"Key": key, "Value": "checked"}])),
        ("ListTagsForResource", lambda: pca.list_tags_for_resource(ResourceArn=arn)),
        ("UntagResource", lambda: pca.untag_resource(ResourceArn=arn, TagKeys=[key])),
    ):
        try:
            call()
            raise AssertionError(
                f"expected {op_name} to reject connection-preferences ARN {arn!r} "
                f"(missing account-id segment) with ValidationException, but it succeeded"
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"]["Message"]
            assert code == "ValidationException", (
                f"{op_name}({arn!r}): expected ValidationException, got {code}: {message}"
            )
            assert message == (
                f"1 validation error detected: Value '{arn}' at 'resourceArn' failed to satisfy "
                "constraint: Member must satisfy regular expression pattern: "
                "arn:[a-z-]+:partnercentral:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9._:/-]+"
            ), f"{op_name}({arn!r}): {message}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
