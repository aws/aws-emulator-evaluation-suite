"""list-tags-for-resource-on-arn-of-wrong-resource-type-answers-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-on-arn-of-wrong-resource-type-answers-not-found"
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
    """A brand profile id placed in a notify-code-configuration ARN names no resource:
    ListTagsForResource answers ResourceNotFoundException for that type and id.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-tagtype-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    arn = eum.get_brand_profile(brandProfileId=bpid)["brandProfileArn"]
    wrong = arn.replace(":brand-profile/", ":notify-code-configuration/", 1)
    assert wrong != arn, f"the ARN {arn!r} does not carry the brand-profile resource type"

    code, message = _error(lambda: eum.list_tags_for_resource(resourceArn=wrong))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == (
        f'Resource not found - ResourceType="notify-code-configuration" ResourceId="{bpid}"'
    ), f"unexpected message {message!r}"

    own = eum.list_tags_for_resource(resourceArn=arn).get("tags", [])
    assert own == [], f"positive control: the real ARN answers its empty tag list, got {own!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
