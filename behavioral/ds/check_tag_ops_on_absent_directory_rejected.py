"""tag-ops-on-absent-directory-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-ops-on-absent-directory-rejected"
GROUP = 'tags'
SERVICES = ['ds']

# ResourceId pattern is ^[d]-[0-9a-f]{10}$ — a directory id and nothing else, so a snapshot id
# is a *validation* failure rather than a not-found. TagKey pattern is
# ^([\p{L}\p{Z}\p{N}_.:/=+\-@]*)$ — note that ':' '.' '/' '=' '+' '-' '@' are all legal, so a key
# containing them must NOT be rejected; '$' is not in the class, so it must be.
_LEGAL_PUNCTUATION_KEY = "sim2real.key:a/b=c+d-e@f"
_ILLEGAL_KEY = "sim2real$key"


def _error_code(fn):
    """Call fn(); return the botocore Error.Code of the ClientError it raises. An unexpected
    success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _absent_directory_id() -> str:
    """A DirectoryId that satisfies the modeled pattern ^d-[0-9a-f]{10}$ but names nothing."""
    return "d-" + uuid.uuid4().hex[:10]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddTagsToResource, RemoveTagsFromResource and ListTagsForResource on an absent directory each fail
    with EntityDoesNotExistException, a malformed ResourceId or a TagKey with '$' fails earlier with
    ValidationException, allowed TagKey punctuation passes validation, and no tag set is created."""
    ds = ctx.client("ds")
    absent = _absent_directory_id()
    tag = [{"Key": "sim2real", "Value": "behavioral"}]

    add = _error_code(lambda: ds.add_tags_to_resource(ResourceId=absent, Tags=tag))
    assert add == "EntityDoesNotExistException", (
        f"AddTagsToResource on absent {absent} must raise EntityDoesNotExistException (the only "
        f"not-found error its shape declares), got {add} — None means it silently succeeded and "
        f"tagged a phantom resource"
    )

    remove = _error_code(
        lambda: ds.remove_tags_from_resource(ResourceId=absent, TagKeys=["sim2real"])
    )
    assert remove == "EntityDoesNotExistException", (
        f"RemoveTagsFromResource on absent {absent} must raise EntityDoesNotExistException, got "
        f"{remove} — None means a no-op success, which hides the missing resource"
    )

    listed = _error_code(lambda: ds.list_tags_for_resource(ResourceId=absent))
    assert listed == "EntityDoesNotExistException", (
        f"ListTagsForResource on absent {absent} must raise EntityDoesNotExistException, got "
        f"{listed} — an empty Tags list here means an emulator that stores nothing passes"
    )

    # A snapshot id is well formed for ITS type but violates the ResourceId pattern, so this is
    # refused by validation, not resolution — a different stage and a different code.
    wrong_type = _error_code(
        lambda: ds.list_tags_for_resource(ResourceId="s-0123456789")
    )
    assert wrong_type == "ValidationException", (
        f"ListTagsForResource(ResourceId='s-0123456789') must be refused with "
        f"ValidationException — the ResourceId pattern is ^[d]-[0-9a-f]{{10}}$, directory ids "
        f"only — got {wrong_type}"
    )
    assert wrong_type != listed, (
        f"a malformed ResourceId and an absent directory must not share one code ({listed!r}); "
        f"they are refused at different stages"
    )

    # TagKey character class: '$' is outside it, so this is a validation failure that must beat
    # resource resolution.
    bad_key = _error_code(
        lambda: ds.add_tags_to_resource(
            ResourceId=absent, Tags=[{"Key": _ILLEGAL_KEY, "Value": "behavioral"}]
        )
    )
    assert bad_key == "ValidationException", (
        f"AddTagsToResource with Key={_ILLEGAL_KEY!r} must be refused with ValidationException "
        f"('$' is outside the TagKey character class) even though the directory is also absent, "
        f"got {bad_key}"
    )
    # ...and the opposite direction: the punctuation the class DOES allow must pass validation
    # and reach resolution.
    legal_key = _error_code(
        lambda: ds.add_tags_to_resource(
            ResourceId=absent, Tags=[{"Key": _LEGAL_PUNCTUATION_KEY, "Value": "behavioral"}]
        )
    )
    assert legal_key == "EntityDoesNotExistException", (
        f"AddTagsToResource with Key={_LEGAL_PUNCTUATION_KEY!r} must PASS validation — "
        f"'.' ':' '/' '=' '+' '-' '@' are all inside the TagKey character class — and fail on "
        f"the absent directory instead, got {legal_key}"
    )

    # Effect absent: the failed writes must not have created a tag set for the phantom id.
    after = _error_code(lambda: ds.list_tags_for_resource(ResourceId=absent))
    assert after == "EntityDoesNotExistException", (
        f"after failed AddTagsToResource calls, ListTagsForResource on {absent} must still "
        f"raise EntityDoesNotExistException, got {after} — anything else means the failed write "
        f"auto-vivified the resource"
    )

    # Control: the account-scoped read path is healthy, so the refusals above are about the
    # resource id and not a broken client, region or credential.
    assert isinstance(
        ds.describe_directories().get("DirectoryDescriptions"), list
    ), "DescribeDirectories must still succeed after the refused tag operations"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
