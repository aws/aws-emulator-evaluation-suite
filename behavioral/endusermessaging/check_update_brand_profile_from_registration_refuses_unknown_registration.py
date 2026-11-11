"""update-brand-profile-from-registration-refuses-unknown-registration."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-brand-profile-from-registration-refuses-unknown-registration"
GROUP = "registrations"
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
    """UpdateBrandProfileFromRegistration refuses a malformed registration id with
    ValidationException and an unknown one with ResourceNotFoundException; the profile is unchanged.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-fromreg-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    attr = "City"
    eum.update_brand_profile_attribute(brandProfileId=bpid, attributeName=attr, attributeValue="Anytown")

    code, message = _error(lambda: eum.update_brand_profile_from_registration(
        brandProfileId=bpid, registrationId="not-a-registration"))
    assert code == "ValidationException", f"malformed: expected ValidationException, got {code}: {message!r}"
    assert message == "registrationId must be a valid registration identifier", (
        f"malformed: unexpected message {message!r}"
    )

    unknown = "registration-" + "0" * 32
    code, message = _error(lambda: eum.update_brand_profile_from_registration(
        brandProfileId=bpid, registrationId=unknown))
    assert code == "ResourceNotFoundException", f"unknown: expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == f'Resource not found - ResourceType="registration" ResourceId="{unknown}"', (
        f"unknown: unexpected message {message!r}"
    )

    assert eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)[
        "attributeValue"] == "Anytown", "a refused import changed the profile's attributes"
    jobs = eum.list_jobs(brandProfileId=bpid)["jobs"]
    assert jobs == [], f"a refused import must start no job, got {len(jobs)}"
    regs = eum.list_registrations_from_brand_profile(brandProfileId=bpid)["registrationAssociations"]
    assert regs == [], f"the profile must have no registrations, got {len(regs)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
