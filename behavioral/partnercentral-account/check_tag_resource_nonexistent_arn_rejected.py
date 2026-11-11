"""tag-resource-nonexistent-arn-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-account"]


def _pca_client(ctx):
    """partnercentral-account is served only from us-east-1. ``region=`` pins that region while
    ctx.client keeps the caller's credentials and endpoint wiring; an emulator serves every
    region on one endpoint, so the same call is correct there."""
    return ctx.client("partnercentral-account", region="us-east-1")


_PARTNER_BENEFIT_DENIED = (
    "This action requires an active AWS Partner benefit. Register as an AWS Partner if you "
    "haven't already, or contact AWS Partner Central Support."
)


def _client_error(fn):
    """Call fn(); return its full parsed response dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a partner-scoped call this account has no benefit for is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource, ListTagsForResource and UntagResource on a well-formed partner ARN fail with
    AccessDeniedException and Reason INCOMPATIBLE_BENEFIT_AWS_PARTNER_STATE, whether or not the partner exists,
    while ListPartners succeeds and never lists the fabricated identifier.
    """
    pca = _pca_client(ctx)
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    fake_partner_id = "partner-" + uuid.uuid4().hex[:13]
    # us-east-1, not ctx.region: partnercentral-account rejects any ARN whose region segment is not
    # us-east-1 with ValidationException/INVALID_VALUE ("region ... is not supported").
    fake_arn = f"arn:aws:partnercentral:us-east-1:{account_id}:catalog/AWS/partner/{fake_partner_id}"

    # Positive control: an unrelated, non-tag call succeeds.
    partners_before = {p["Id"] for p in pca.list_partners(Catalog="AWS")["PartnerSummaryList"]}
    assert fake_partner_id not in partners_before, "fabricated id already present before the probe"

    for op_name, fn in (
        ("TagResource", lambda: pca.tag_resource(ResourceArn=fake_arn, Tags=[{"Key": "k", "Value": "v"}])),
        ("ListTagsForResource", lambda: pca.list_tags_for_resource(ResourceArn=fake_arn)),
        ("UntagResource", lambda: pca.untag_resource(ResourceArn=fake_arn, TagKeys=["k"])),
    ):
        resp = _client_error(fn)
        code = resp.get("Error", {}).get("Code")
        reason = resp.get("Reason")
        assert code == "AccessDeniedException", f"{op_name}(fake partner arn): expected AccessDeniedException, got {code}"
        assert reason == "INCOMPATIBLE_BENEFIT_AWS_PARTNER_STATE", (
            f"{op_name}(fake partner arn): expected reason INCOMPATIBLE_BENEFIT_AWS_PARTNER_STATE, "
            f"got {reason} ({resp.get('Error', {}).get('Message')})"
        )
        assert resp["Error"]["Message"] == _PARTNER_BENEFIT_DENIED, f"{op_name}: {resp['Error']}"

    # Effect absent: the fabricated partner never surfaces in the account's own partner list.
    partners_after = {p["Id"] for p in pca.list_partners(Catalog="AWS")["PartnerSummaryList"]}
    assert fake_partner_id not in partners_after, f"fabricated id {fake_partner_id} unexpectedly present after the probe"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
