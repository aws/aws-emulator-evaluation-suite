"""brand-profile-tags-are-unreachable-after-profile-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "brand-profile-tags-are-unreachable-after-profile-delete"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once a tagged brand profile is deleted, ListTagsForResource on its ARN answers
    ResourceNotFoundException naming the profile instead of an empty tag list.
    """
    eum = ctx.client("endusermessaging")
    created = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-tagdel-"),
        tags=[{"key": "team", "value": "alpha"}],
    )
    bpid, arn = created["brandProfileId"], created["brandProfileArn"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))

    before = eum.list_tags_for_resource(resourceArn=arn)["tags"]
    assert before == [{"key": "team", "value": "alpha"}], f"tags before delete, got {before!r}"

    eum.delete_brand_profile(brandProfileId=bpid)

    code, message = _error(lambda: eum.list_tags_for_resource(resourceArn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == f'Resource not found - ResourceType="brand-profile" ResourceId="{bpid}"', (
        f"unexpected message {message!r}"
    )
    code, message = _error(lambda: eum.tag_resource(resourceArn=arn, tags=[{"key": "k", "value": "v"}]))
    assert code == "ResourceNotFoundException", (
        f"TagResource on the deleted profile, expected ResourceNotFoundException, got {code}: {message!r}"
    )
    assert message == f'Resource not found - ResourceType="brand-profile" ResourceId="{bpid}"', (
        f"unexpected message {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
