"""update-brand-profile-attribute-rejects-request-with-no-fields."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-brand-profile-attribute-rejects-request-with-no-fields"
GROUP = "brand-profile-attributes"
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
    """UpdateBrandProfileAttribute naming no member to change is refused with
    ValidationException and leaves the attribute as it was; a named member then applies.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-attrnone-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    attr = "Untouched Note"
    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": attr, "attributeType": "TEXT", "attributeValue": "same"}])

    code, message = _error(lambda: eum.update_brand_profile_attribute(brandProfileId=bpid, attributeName=attr))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "At least one field must be provided for update", f"unexpected message {message!r}"
    assert eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)[
        "attributeValue"] == "same", "the refused update changed the value"

    eum.update_brand_profile_attribute(brandProfileId=bpid, attributeName=attr, attributeValue="changed")
    assert eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)[
        "attributeValue"] == "changed", "positive control: a named member must apply"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
