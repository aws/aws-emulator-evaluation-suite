"""get-brand-profile-accepts-arn-and-rejects-name-as-identifier."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-brand-profile-accepts-arn-and-rejects-name-as-identifier"
GROUP = "brand-profiles"
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
    """GetBrandProfile resolves a profile by its id or its ARN to the same record, but refuses
    the profile's name as an identifier with ValidationException.
    """
    eum = ctx.client("endusermessaging")
    name = ctx.unique_name("sim2real-behav-eum-ident-")
    created = eum.create_brand_profile(brandProfileName=name)
    bpid, arn = created["brandProfileId"], created["brandProfileArn"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))

    by_id = eum.get_brand_profile(brandProfileId=bpid)
    by_arn = eum.get_brand_profile(brandProfileId=arn)
    for key in ("brandProfileId", "brandProfileArn", "brandProfileName"):
        assert by_id[key] == by_arn[key], f"{key}: by id {by_id[key]!r}, by ARN {by_arn[key]!r}"

    code, message = _error(lambda: eum.get_brand_profile(brandProfileId=name))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == f"invalid brand profile ID format: {name}", f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
