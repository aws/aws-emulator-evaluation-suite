"""brand-profile-attribute-category-must-be-a-supported-value."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "brand-profile-attribute-category-must-be-a-supported-value"
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
    """An attribute category outside the supported set is refused on create and on update with
    ValidationException listing the set, and the stored category is unchanged.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-cat-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    supported = ("BUSINESS_IDENTITY, BUSINESS_ADDRESS, BUSINESS_CONTACT, MESSAGING_USE_CASE, "
                 "OPT_IN_CONSENT, MESSAGE_CONTENT, COMPLIANCE_KEYWORDS, TERMS_AND_POLICY, "
                 "BRAND_DISPLAY, SUPPORTING_DOCUMENT, OTHER")
    attr = "Category Note"
    code, message = _error(lambda: eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": attr, "attributeType": "TEXT", "attributeValue": "v", "category": "MARKETING"}]))
    assert code == "ValidationException", f"create: expected ValidationException, got {code}: {message!r}"
    assert message == f"Invalid category 'MARKETING'. Supported values: {supported}", (
        f"create: unexpected message {message!r}"
    )

    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": attr, "attributeType": "TEXT", "attributeValue": "v", "category": "OTHER"}])
    code, message = _error(lambda: eum.update_brand_profile_attribute(
        brandProfileId=bpid, attributeName=attr, category="business_contact"))
    assert code == "ValidationException", f"update: expected ValidationException, got {code}: {message!r}"
    assert message == f"Invalid category 'business_contact'. Supported values: {supported}", (
        f"update: unexpected message {message!r}"
    )
    got = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)
    assert got["category"] == "OTHER", f"the stored category changed to {got['category']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
