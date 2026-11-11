"""brand-profile-deletion-protection-blocks-then-allows-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "brand-profile-deletion-protection-blocks-then-allows-delete"
GROUP = 'brand-profiles'
SERVICES = ['endusermessaging']


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
    """A deletion-protected brand profile refuses DeleteBrandProfile with ConflictException;
    turning protection off through UpdateBrandProfile is what makes the same delete succeed.
    """
    eum = ctx.client("endusermessaging")
    name = ctx.unique_name("sim2real-behav-eum-bpdp-")

    created = eum.create_brand_profile(brandProfileName=name, deletionProtectionEnabled=True)
    bpid = created["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    assert created["deletionProtectionEnabled"] is True, (
        f"expected deletionProtectionEnabled True, got {created['deletionProtectionEnabled']!r}"
    )

    code, message = _error(lambda: eum.delete_brand_profile(brandProfileId=bpid))
    assert code == "ConflictException", f"expected ConflictException while protected, got {code}: {message!r}"
    assert message == (
        'Conflict occurred - Reason="DELETION_PROTECTION_ENABLED" ResourceType="brand-profile"'
    ), f"unexpected message {message!r}"

    still_there = eum.get_brand_profile(brandProfileId=bpid)
    assert still_there["status"] == "ACTIVE", (
        f"profile should still exist after the refused delete, got status {still_there['status']!r}"
    )

    updated = eum.update_brand_profile(brandProfileId=bpid, deletionProtectionEnabled=False)
    assert updated["deletionProtectionEnabled"] is False, (
        f"expected deletionProtectionEnabled False after update, got {updated['deletionProtectionEnabled']!r}"
    )

    eum.delete_brand_profile(brandProfileId=bpid)
    code, message = _error(lambda: eum.get_brand_profile(brandProfileId=bpid))
    assert code == "ResourceNotFoundException", (
        f"expected the profile to be gone once protection was off, got {code}: {message!r}"
    )
    assert message == f'Resource not found - ResourceType="brand-profile" ResourceId="{bpid}"', (
        f"unexpected message {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
