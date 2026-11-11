"""deletion-protection-does-not-block-attribute-deletes."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deletion-protection-does-not-block-attribute-deletes"
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
    """Deletion protection guards only the profile itself: an attribute of a protected profile
    is deleted normally while DeleteBrandProfile stays refused.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(brandProfileName=ctx.unique_name("sim2real-behav-eum-protattr-"),
                                    deletionProtectionEnabled=True)["brandProfileId"]

    def _unprotect_and_delete():
        try:
            eum.update_brand_profile(brandProfileId=bpid, deletionProtectionEnabled=False)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        eum.delete_brand_profile(brandProfileId=bpid)

    ctx.on_cleanup(_unprotect_and_delete)

    attr = "Protected Note"
    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": attr, "attributeType": "TEXT", "attributeValue": "keep me"}])
    eum.delete_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)

    code, message = _error(lambda: eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr))
    assert code == "ResourceNotFoundException", (
        f"the attribute must be gone despite profile protection, got {code}: {message!r}"
    )
    assert message == 'Resource not found - ResourceType="brand-profile-attribute"', (
        f"unexpected message {message!r}"
    )

    code, message = _error(lambda: eum.delete_brand_profile(brandProfileId=bpid))
    assert code == "ConflictException", f"the profile must stay protected, got {code}: {message!r}"
    assert message == (
        'Conflict occurred - Reason="DELETION_PROTECTION_ENABLED" ResourceType="brand-profile"'
    ), f"unexpected message {message!r}"
    assert eum.get_brand_profile(brandProfileId=bpid)["status"] == "ACTIVE", "the profile must remain"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
