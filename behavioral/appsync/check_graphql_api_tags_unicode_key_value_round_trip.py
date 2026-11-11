"""graphql-api-tags-unicode-key-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "graphql-api-tags-unicode-key-value-round-trip"
GROUP = "tags"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a tag whose key/value has Unicode outside the documented charset.

    An in-charset key/value, including + - = . : / @ and spaces, round-trips byte-for-byte.

    Reference: https://docs.aws.amazon.com/appsync/latest/APIReference/API_TagResource.html"""
    appsync = ctx.client("appsync")
    api_id, api_arn = _create_graphql_api(ctx)

    unicode_key = "Unicode_Tag_\u65e5\u672c\u8a9e"
    unicode_value = "val-\U0001f389-\u03b8"
    try:
        appsync.tag_resource(resourceArn=api_arn, tags={unicode_key: unicode_value})
        raise AssertionError(
            "TagResource accepted a unicode tag key/value; AWS is documented to "
            "restrict tags to an ASCII charset and should have raised BadRequestException"
        )
    except appsync.exceptions.BadRequestException as exc:
        expected = ("Tags can only contain letters, numbers, spaces, and the following special "
                    "characters: _ . : / = + - @")
        message = exc.response["Error"].get("Message")
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    allowed_key = "Plain+Tag.Key:1/A"
    allowed_value = "plain-value=1.2:3/four@five 6"

    appsync.tag_resource(resourceArn=api_arn, tags={allowed_key: allowed_value})

    list_resp = appsync.list_tags_for_resource(resourceArn=api_arn)
    tags = list_resp["tags"]

    assert tags.get(allowed_key) == allowed_value, (
        f"in-charset tag mangled: key={allowed_key!r} got value={tags.get(allowed_key)!r} "
        f"expected={allowed_value!r}"
    )
    assert unicode_key not in tags, "rejected unicode tag key should not have been persisted"


def _create_graphql_api(ctx) -> tuple[str, str]:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(name=name, authenticationType="API_KEY")
    api_id = resp["graphqlApi"]["apiId"]
    api_arn = resp["graphqlApi"]["arn"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id, api_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
