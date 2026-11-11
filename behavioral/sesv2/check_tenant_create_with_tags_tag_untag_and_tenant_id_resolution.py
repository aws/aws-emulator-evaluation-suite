"""tenant-create-with-tags-tag-untag-and-tenant-id-resolution."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tenant-create-with-tags-tag-untag-and-tenant-id-resolution"
GROUP = "tenants"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTenant's inline Tags, TagResource and UntagResource are reflected by
    ListTagsForResource, and an ARN with the real name but a fabricated tenantId segment is
    rejected NotFoundException with a message naming both.
    """
    sesv2 = ctx.client("sesv2")

    tenant_name = ctx.unique_name("sim2real-tenant-")
    created = sesv2.create_tenant(TenantName=tenant_name, Tags=[{"Key": "env", "Value": "dev"}])
    ctx.on_cleanup(lambda: sesv2.delete_tenant(TenantName=tenant_name))
    tenant_arn = created["TenantArn"]
    assert tenant_arn.count("/") == 2, f"expected a two-segment tenant ARN, got {tenant_arn!r}"
    tenant_id = tenant_arn.rsplit("/", 1)[-1]

    listed = sesv2.list_tags_for_resource(ResourceArn=tenant_arn)["Tags"]
    assert listed == [{"Key": "env", "Value": "dev"}], (
        f"expected the tenant's inline creation tag to be visible, got {listed!r}"
    )

    sesv2.tag_resource(ResourceArn=tenant_arn, Tags=[{"Key": "owner", "Value": "alice"}])
    after_tag = sesv2.list_tags_for_resource(ResourceArn=tenant_arn)["Tags"]
    expected_after_tag = [{"Key": "env", "Value": "dev"}, {"Key": "owner", "Value": "alice"}]
    assert sorted(after_tag, key=lambda t: t["Key"]) == expected_after_tag, (
        f"expected tags {expected_after_tag!r} after TagResource, got {after_tag!r}"
    )

    sesv2.untag_resource(ResourceArn=tenant_arn, TagKeys=["env"])
    after_untag = sesv2.list_tags_for_resource(ResourceArn=tenant_arn)["Tags"]
    assert after_untag == [{"Key": "owner", "Value": "alice"}], (
        f"expected only the 'owner' tag to remain after UntagResource, got {after_untag!r}"
    )

    # The tenant ARN is tenant/<name>/<tenantId>; the tenantId segment is what resolves it.
    bogus_tenant_id = "tn-000000000000000000000000000000"
    bogus_arn = tenant_arn[: tenant_arn.rfind("/")] + "/" + bogus_tenant_id
    assert bogus_tenant_id != tenant_id, "the fabricated tenantId must differ from the real one"
    err = _client_error(lambda: sesv2.list_tags_for_resource(ResourceArn=bogus_arn))
    assert err.response["Error"]["Code"] == "NotFoundException", (
        f"expected NotFoundException for a real tenant name with a wrong tenantId, got "
        f"{err.response['Error']!r}"
    )
    message = err.response["Error"].get("Message", "")
    # Real AWS joins the two clauses with no space between the name and "with".
    expected_message = f"No Tenant present with name: {tenant_name}with tenantId: {bogus_tenant_id}"
    assert message == expected_message, (
        f"expected the NotFoundException message {expected_message!r} naming the tenant name and "
        f"the fabricated tenantId, got {message!r}"
    )

    # positive control: the real ARN still resolves after the failed lookup above
    still_there = sesv2.list_tags_for_resource(ResourceArn=tenant_arn)["Tags"]
    assert still_there == [{"Key": "owner", "Value": "alice"}], (
        f"expected the real tenant ARN to still resolve after the bogus-tenantId probe, "
        f"got {still_there!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
