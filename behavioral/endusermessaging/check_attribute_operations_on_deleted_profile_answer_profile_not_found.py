"""attribute-operations-on-deleted-profile-answer-profile-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attribute-operations-on-deleted-profile-answer-profile-not-found"
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
    """After DeleteBrandProfile every attribute operation on the profile, delete included, is
    refused with ResourceNotFoundException naming the profile, not the attribute.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-gone-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    attr = "Contact Note"
    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": attr, "attributeType": "TEXT", "attributeValue": "before"}])
    assert eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)[
        "attributeValue"] == "before", "positive control: the attribute is readable before the delete"

    eum.delete_brand_profile(brandProfileId=bpid)
    expected = f'Resource not found - ResourceType="brand-profile" ResourceId="{bpid}"'
    calls = {
        "GetBrandProfileAttribute": lambda: eum.get_brand_profile_attribute(
            brandProfileId=bpid, attributeName=attr),
        "UpdateBrandProfileAttribute": lambda: eum.update_brand_profile_attribute(
            brandProfileId=bpid, attributeName=attr, attributeValue="after"),
        "DeleteBrandProfileAttribute": lambda: eum.delete_brand_profile_attribute(
            brandProfileId=bpid, attributeName=attr),
        "CreateBrandProfileAttributes": lambda: eum.create_brand_profile_attributes(
            brandProfileId=bpid,
            attributes=[{"attributeName": "Other", "attributeType": "TEXT", "attributeValue": "x"}]),
        "ListBrandProfileAttributes": lambda: eum.list_brand_profile_attributes(brandProfileId=bpid),
    }
    for op, call in calls.items():
        code, message = _error(call)
        assert (code, message) == ("ResourceNotFoundException", expected), (
            f"{op} on the deleted profile: expected ResourceNotFoundException {expected!r}, "
            f"got {code}: {message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
