"""tag-resource-value-with-special-characters-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-value-with-special-characters-round-trip"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tag values containing special/unicode characters and empty-string values
    are preserved exactly through TagResource/ListTagsForResource."""
    cognito = ctx.client("cognito-identity")

    pool_name = ctx.unique_name("sim2real-idp-")
    created = cognito.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
    )
    pool_id = created["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id))
    resource_arn = _pool_arn(ctx, pool_id)

    # TagValueType only constrains length (0-256), not character class -- exercise
    # the full punctuation set from AWS's generic tagging convention (_ . : / = + - @)
    # plus an empty-string value, and confirm none of it is stripped or rejected.
    tags = {
        "empty-value": "",
        "special-chars": "_.:/=+-@",
        "mixed-special": "path/to:thing_v1.0+build=42-final@host",
        "whitespace-padded": "  leading and trailing  ",
    }

    cognito.tag_resource(ResourceArn=resource_arn, Tags=tags)

    listed = cognito.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    for key, value in tags.items():
        assert key in listed, f"tag {key!r} missing from ListTagsForResource: {listed!r}"
        assert listed[key] == value, f"tag {key!r} value mismatch: {listed[key]!r} != {value!r}"
        assert list(listed[key]) == list(value), (
            f"tag {key!r} value byte-mangled: {listed[key]!r} != {value!r}"
        )


def _pool_arn(ctx, pool_id: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
