"""contact-list-create-with-tags-tag-untag-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "contact-list-create-with-tags-tag-untag-lifecycle"
GROUP = "contacts-v2"
SERVICES = ["sesv2"]


@tags("resource:account-singleton:sesv2-contact-list", "axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateContactList's inline Tags are visible via ListTagsForResource and GetContactList,
    and TagResource/UntagResource then add and remove tags on the same contact list.
    """
    sesv2 = ctx.client("sesv2")

    existing = sesv2.list_contact_lists().get("ContactLists", [])
    if existing:
        raise AssertionError(
            f"account already has a contact list ({existing!r}); SESv2 permits exactly one "
            "per account, so this check cannot safely create its own without disrupting "
            "shared account state"
        )

    name = ctx.unique_name("sim2real-contactlist-")
    sesv2.create_contact_list(
        ContactListName=name,
        Tags=[{"Key": "env", "Value": "dev"}, {"Key": "team", "Value": "platform"}],
    )
    ctx.on_cleanup(lambda: sesv2.delete_contact_list(ContactListName=name))
    resource_arn = f"arn:aws:ses:{ctx.region}:{ctx.account}:contact-list/{name}"

    listed = sesv2.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    expected_created = [{"Key": "env", "Value": "dev"}, {"Key": "team", "Value": "platform"}]
    assert sorted(listed, key=lambda t: t["Key"]) == expected_created, (
        f"expected tags {expected_created!r} from ListTagsForResource, got {listed!r}"
    )

    got = sesv2.get_contact_list(ContactListName=name)
    got_tags = sorted(got["Tags"], key=lambda t: t["Key"])
    assert got_tags == expected_created, (
        f"expected GetContactList Tags {expected_created!r}, got {got_tags!r}"
    )

    sesv2.tag_resource(ResourceArn=resource_arn, Tags=[{"Key": "owner", "Value": "alice"}])
    after_tag = sesv2.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    expected_after_tag = sorted(
        expected_created + [{"Key": "owner", "Value": "alice"}], key=lambda t: t["Key"]
    )
    assert sorted(after_tag, key=lambda t: t["Key"]) == expected_after_tag, (
        f"expected tags {expected_after_tag!r} after TagResource, got {after_tag!r}"
    )

    sesv2.untag_resource(ResourceArn=resource_arn, TagKeys=["env", "team"])
    after_untag = sesv2.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    assert after_untag == [{"Key": "owner", "Value": "alice"}], (
        f"expected only the 'owner' tag to remain after UntagResource, got {after_untag!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
