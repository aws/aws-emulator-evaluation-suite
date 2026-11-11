"""tenant-tag-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tenant-tag-unicode-round-trip"
GROUP = "server-side"
SERVICES = ["sesv2"]

# SESv2 tag values allow letters (accented Latin included), numbers, spaces and _.:/=+@-;
# CJK ideographs and emoji are rejected.
_UNICODE_VALUE = "caf\u00e9-m\u00fcnchen-\u00e5ngstr\u00f6m"
_DISALLOWED_VALUE = "\u65e5\u672c\u8a9e-\U0001f600"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Accented Latin letters in a tenant tag value round-trip exactly through ListTagsForResource,
    while CJK ideographs and emoji are rejected with BadRequestException and the charset message."""
    sesv2 = ctx.client("sesv2")
    tenant_name = ctx.unique_name("sim2real-tenant-tag-")
    created = sesv2.create_tenant(TenantName=tenant_name)
    ctx.on_cleanup(lambda: sesv2.delete_tenant(TenantName=tenant_name))
    tenant_arn = created["TenantArn"]

    sesv2.tag_resource(ResourceArn=tenant_arn, Tags=[{"Key": "sim2real-unicode", "Value": _UNICODE_VALUE}])

    tags = sesv2.list_tags_for_resource(ResourceArn=tenant_arn)["Tags"]
    matching = [t for t in tags if t["Key"] == "sim2real-unicode"]
    assert len(matching) == 1, f"expected exactly one matching tag, got {matching}"
    assert matching[0]["Value"] == _UNICODE_VALUE, (
        f"unicode tag value corrupted: expected {_UNICODE_VALUE!r}, got {matching[0]['Value']!r}"
    )

    from botocore.exceptions import ClientError

    try:
        sesv2.tag_resource(ResourceArn=tenant_arn, Tags=[{"Key": "sim2real-bad-unicode", "Value": _DISALLOWED_VALUE}])
    except ClientError as err:
        assert err.response["Error"]["Code"] == "BadRequestException", (
            f"expected BadRequestException for disallowed tag charset, got {err.response['Error']['Code']}"
        )
        expected_msg = (
            "Tags can only contain letters, numbers, spaces, and the following special characters: "
            "_ . : / = + - @"
        )
        assert err.response["Error"].get("Message") == expected_msg, (
            f"expected message {expected_msg!r}, got {err.response['Error'].get('Message')!r}"
        )
    else:
        raise AssertionError("TagResource accepted a tag value outside the allowed charset")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
