"""tag-resource-rejects-duplicate-keys-in-one-request."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-rejects-duplicate-keys-in-one-request"
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
    """TagResource refuses a request that names the same key twice with ValidationException and
    applies neither value.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-tagdup-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    arn = eum.get_brand_profile(brandProfileId=bpid)["brandProfileArn"]
    eum.tag_resource(resourceArn=arn, tags=[{"key": "team", "value": "original"}])

    code, message = _error(lambda: eum.tag_resource(
        resourceArn=arn, tags=[{"key": "team", "value": "one"}, {"key": "team", "value": "two"}]
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "Duplicate tag key: 'team'", f"unexpected message {message!r}"

    tags_now = eum.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_now == [{"key": "team", "value": "original"}], (
        f"the refused request must leave the tag unchanged, got {tags_now!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
