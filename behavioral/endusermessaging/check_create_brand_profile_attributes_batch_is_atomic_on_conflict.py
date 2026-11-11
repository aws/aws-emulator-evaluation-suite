"""create-brand-profile-attributes-batch-is-atomic-on-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-brand-profile-attributes-batch-is-atomic-on-conflict"
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
    """A CreateBrandProfileAttributes batch holding one new name and one existing name is
    refused with ConflictException and creates neither; the new name alone then succeeds.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-atomic-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    existing, fresh = "Existing Note", "Fresh Note"
    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": existing, "attributeType": "TEXT", "attributeValue": "first"}])

    code, message = _error(lambda: eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": fresh, "attributeType": "TEXT", "attributeValue": "new"},
        {"attributeName": existing, "attributeType": "TEXT", "attributeValue": "second"},
    ]))
    assert code == "ConflictException", f"expected ConflictException, got {code}: {message!r}"
    assert message == (
        'Conflict occurred - Reason="RESOURCE_ALREADY_EXISTS" ResourceType="brand-profile-attribute"'
    ), f"unexpected message {message!r}"

    code, message = _error(lambda: eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=fresh))
    assert code == "ResourceNotFoundException", (
        f"the refused batch must not create {fresh!r}, got {code}: {message!r}"
    )
    kept = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=existing)
    assert kept["attributeValue"] == "first", f"the existing value changed to {kept['attributeValue']!r}"

    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": fresh, "attributeType": "TEXT", "attributeValue": "new"}])
    got = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=fresh)
    assert got["attributeValue"] == "new", f"positive control, got {got['attributeValue']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
