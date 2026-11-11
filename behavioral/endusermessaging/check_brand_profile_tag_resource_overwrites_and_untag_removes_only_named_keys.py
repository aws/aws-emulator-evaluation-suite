"""brand-profile-tag-resource-overwrites-and-untag-removes-only-named-keys."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "brand-profile-tag-resource-overwrites-and-untag-removes-only-named-keys"
GROUP = "tags"
SERVICES = ["endusermessaging"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource overwrites the value of an existing key and adds a new one; UntagResource
    removes only the keys it names and ignores a key the resource never had.
    """
    eum = ctx.client("endusermessaging")
    created = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-tags-"),
        tags=[{"key": "team", "value": "alpha"}, {"key": "stage", "value": "test"}],
    )
    bpid, arn = created["brandProfileId"], created["brandProfileArn"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))

    def _tags():
        return {t["key"]: t["value"] for t in eum.list_tags_for_resource(resourceArn=arn)["tags"]}

    first = _tags()
    assert first == {"team": "alpha", "stage": "test"}, f"tags at create, got {first!r}"

    eum.tag_resource(resourceArn=arn, tags=[{"key": "team", "value": "beta"},
                                            {"key": "owner", "value": "ops"}])
    second = _tags()
    assert second == {"team": "beta", "stage": "test", "owner": "ops"}, (
        f"TagResource must overwrite team and add owner, got {second!r}"
    )

    eum.untag_resource(resourceArn=arn, tagKeys=["stage", "never-set"])
    third = _tags()
    assert third == {"team": "beta", "owner": "ops"}, (
        f"UntagResource must remove only stage, got {third!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
