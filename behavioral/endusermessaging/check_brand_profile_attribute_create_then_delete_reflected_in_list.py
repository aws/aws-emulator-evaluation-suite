"""brand-profile-attribute-create-then-delete-reflected-in-list."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "brand-profile-attribute-create-then-delete-reflected-in-list"
GROUP = 'brand-profile-attributes'
SERVICES = ['endusermessaging']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _custom_names(eum, bpid: str, *expected: str) -> set[str]:
    pages = eum.get_paginator("list_brand_profile_attributes").paginate(
        brandProfileId=bpid, PaginationConfig={"PageSize": 10}
    )
    names = {a["attributeName"] for page in pages for a in page["brandProfileAttributes"]}
    return names & set(expected)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two custom attributes both appear in ListBrandProfileAttributes once created; deleting
    one removes exactly that one from the list while the other stays.
    """
    eum = ctx.client("endusermessaging")
    bp_name = ctx.unique_name("sim2real-behav-eum-attrlist-")
    keep_name = ctx.unique_name("sim2real-behav-eum-attr-keep-")
    drop_name = ctx.unique_name("sim2real-behav-eum-attr-drop-")

    bpid = eum.create_brand_profile(brandProfileName=bp_name)["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))

    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": keep_name, "attributeType": "TEXT", "attributeValue": "keep"},
        {"attributeName": drop_name, "attributeType": "TEXT", "attributeValue": "drop"},
    ])

    seen = _custom_names(eum, bpid, keep_name, drop_name)
    assert seen == {keep_name, drop_name}, f"expected both custom attributes listed, got {seen!r}"

    eum.delete_brand_profile_attribute(brandProfileId=bpid, attributeName=drop_name)

    seen = _custom_names(eum, bpid, keep_name, drop_name)
    assert seen == {keep_name}, f"expected only {keep_name!r} left among our custom attributes, got {seen!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
