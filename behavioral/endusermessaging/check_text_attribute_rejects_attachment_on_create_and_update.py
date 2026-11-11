"""text-attribute-rejects-attachment-on-create-and-update."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "text-attribute-rejects-attachment-on-create-and-update"
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
    """A TEXT attribute never takes an attachment: CreateBrandProfileAttributes and
    UpdateBrandProfileAttribute both refuse one with ValidationException and the value stays.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-textatt-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    attr = "Plain Note"
    code, message = _error(lambda: eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": attr, "attributeType": "TEXT", "attachmentBody": b"abc"}]))
    assert code == "ValidationException", f"create: expected ValidationException, got {code}: {message!r}"
    assert message == f"attachmentBody cannot be provided for TEXT attribute '{attr}'", (
        f"create: unexpected message {message!r}"
    )

    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": attr, "attributeType": "TEXT", "attributeValue": "kept"}])
    code, message = _error(lambda: eum.update_brand_profile_attribute(
        brandProfileId=bpid, attributeName=attr, attachmentBody=b"abc"))
    assert code == "ValidationException", f"update: expected ValidationException, got {code}: {message!r}"
    assert message == "attachmentBody cannot be provided for TEXT attribute", (
        f"update: unexpected message {message!r}"
    )
    got = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)
    assert got["attributeValue"] == "kept", f"value changed to {got['attributeValue']!r}"
    assert "mediaContentType" not in got, f"a TEXT attribute gained media: {got.get('mediaContentType')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
