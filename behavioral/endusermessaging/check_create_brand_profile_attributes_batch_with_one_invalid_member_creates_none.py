"""create-brand-profile-attributes-batch-with-one-invalid-member-creates-none."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-brand-profile-attributes-batch-with-one-invalid-member-creates-none"
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
    """A batch whose second member is a TEXT attribute carrying an attachment is refused with
    ValidationException naming it, and the valid first member is not created either.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-batchinv-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    good, bad = "Valid Note", "Invalid Note"
    code, message = _error(lambda: eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": good, "attributeType": "TEXT", "attributeValue": "ok"},
        {"attributeName": bad, "attributeType": "TEXT", "attachmentBody": b"x"},
    ]))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == f"attachmentBody cannot be provided for TEXT attribute '{bad}'", (
        f"unexpected message {message!r}"
    )
    code, message = _error(lambda: eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=good))
    assert code == "ResourceNotFoundException", (
        f"the valid member of a refused batch must not be created, got {code}: {message!r}"
    )

    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": good, "attributeType": "TEXT", "attributeValue": "ok"}])
    assert eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=good)[
        "attributeValue"] == "ok", "positive control: the valid member alone is created"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
