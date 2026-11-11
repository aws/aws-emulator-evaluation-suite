"""list-tags-for-resource-rejects-arn-from-another-region."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-rejects-arn-from-another-region"
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
    """ListTagsForResource refuses the ARN of a profile rewritten to another Region with a
    ValidationException naming both Regions, while the real ARN answers its tags.
    """
    eum = ctx.client("endusermessaging")
    created = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-tagreg-"),
        tags=[{"key": "team", "value": "alpha"}],
    )
    bpid, arn = created["brandProfileId"], created["brandProfileArn"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))

    other = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"
    foreign_arn = arn.replace(f":{ctx.region}:", f":{other}:", 1)
    assert foreign_arn != arn, f"the ARN {arn!r} does not carry the Region {ctx.region!r}"

    code, message = _error(lambda: eum.list_tags_for_resource(resourceArn=foreign_arn))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == (
        f"ARN partition/region mismatch: expected partition 'aws' region '{ctx.region}', "
        f"got partition 'aws' region '{other}'"
    ), f"unexpected message {message!r}"

    own = eum.list_tags_for_resource(resourceArn=arn)["tags"]
    assert own == [{"key": "team", "value": "alpha"}], f"positive control, got {own!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
