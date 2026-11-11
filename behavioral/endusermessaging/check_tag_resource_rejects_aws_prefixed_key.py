"""tag-resource-rejects-aws-prefixed-key."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-rejects-aws-prefixed-key"
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
    """TagResource refuses a key in the reserved aws: namespace with ValidationException and
    leaves the resource's tags as they were; an ordinary key is accepted.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-tagaws-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    arn = eum.get_brand_profile(brandProfileId=bpid)["brandProfileArn"]

    code, message = _error(lambda: eum.tag_resource(
        resourceArn=arn, tags=[{"key": "aws:reserved", "value": "v"}, {"key": "team", "value": "x"}]
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "Tag key cannot start with 'aws:': aws:reserved", f"unexpected message {message!r}"
    after_refusal = eum.list_tags_for_resource(resourceArn=arn).get("tags", [])
    assert after_refusal == [], f"the refused request must add no tag, got {after_refusal!r}"

    eum.tag_resource(resourceArn=arn, tags=[{"key": "team", "value": "x"}])
    accepted = eum.list_tags_for_resource(resourceArn=arn)["tags"]
    assert accepted == [{"key": "team", "value": "x"}], f"positive control, got {accepted!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
