"""update-brand-profile-attribute-partial-update-preserves-other-fields."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-brand-profile-attribute-partial-update-preserves-other-fields"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateBrandProfileAttribute changes only the members it names: a description-only update
    keeps value and category, and an empty value clears the value alone.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-partial-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    attr = "Partial Note"
    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": attr, "attributeType": "TEXT", "attributeValue": "original",
         "description": "first description", "category": "BUSINESS_CONTACT"}])

    eum.update_brand_profile_attribute(brandProfileId=bpid, attributeName=attr,
                                       description="second description")
    got = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)
    assert (got["attributeValue"], got["description"], got["category"]) == (
        "original", "second description", "BUSINESS_CONTACT"), (
        f"after a description update: {got['attributeValue']!r}, {got['description']!r}, {got['category']!r}"
    )

    eum.update_brand_profile_attribute(brandProfileId=bpid, attributeName=attr, attributeValue="")
    got = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)
    assert (got["attributeValue"], got["description"], got["category"]) == (
        "", "second description", "BUSINESS_CONTACT"), (
        f"after clearing the value: {got.get('attributeValue')!r}, {got['description']!r}, {got['category']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
