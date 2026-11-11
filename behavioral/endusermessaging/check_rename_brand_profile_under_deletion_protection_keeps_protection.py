"""rename-brand-profile-under-deletion-protection-keeps-protection."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rename-brand-profile-under-deletion-protection-keeps-protection"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateBrandProfile renames a deletion-protected profile; Get and List show the new name
    and protection still blocks DeleteBrandProfile.
    """
    eum = ctx.client("endusermessaging")
    old_name = ctx.unique_name("sim2real-behav-eum-rename-")
    new_name = ctx.unique_name("sim2real-behav-eum-renamed-")
    bpid = eum.create_brand_profile(brandProfileName=old_name,
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

    updated = eum.update_brand_profile(brandProfileId=bpid, brandProfileName=new_name)
    assert updated["brandProfileName"] == new_name, f"update answered {updated['brandProfileName']!r}"
    assert updated["deletionProtectionEnabled"] is True, (
        f"renaming must keep protection, got {updated['deletionProtectionEnabled']!r}"
    )

    got = eum.get_brand_profile(brandProfileId=bpid)
    assert got["brandProfileName"] == new_name, f"GetBrandProfile name {got['brandProfileName']!r}"
    listed = None
    for page in eum.get_paginator("list_brand_profiles").paginate():
        for item in page["brandProfiles"]:
            if item["brandProfileId"] == bpid:
                listed = item["brandProfileName"]
    assert listed == new_name, f"ListBrandProfiles must show {new_name!r}, got {listed!r}"

    code, message = _error(lambda: eum.delete_brand_profile(brandProfileId=bpid))
    assert code == "ConflictException", f"expected ConflictException, got {code}: {message!r}"
    assert message == (
        'Conflict occurred - Reason="DELETION_PROTECTION_ENABLED" ResourceType="brand-profile"'
    ), f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
