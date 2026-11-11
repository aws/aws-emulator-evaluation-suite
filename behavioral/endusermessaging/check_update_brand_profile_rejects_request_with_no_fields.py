"""update-brand-profile-rejects-request-with-no-fields."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-brand-profile-rejects-request-with-no-fields"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateBrandProfile with neither a name nor a protection setting is refused with
    ValidationException and changes nothing; the same call with a name succeeds.
    """
    eum = ctx.client("endusermessaging")
    name = ctx.unique_name("sim2real-behav-eum-updnone-")
    bpid = eum.create_brand_profile(brandProfileName=name)["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))

    code, message = _error(lambda: eum.update_brand_profile(brandProfileId=bpid))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "At least one field must be provided for update", f"unexpected message {message!r}"

    got = eum.get_brand_profile(brandProfileId=bpid)
    assert (got["brandProfileName"], got["deletionProtectionEnabled"]) == (name, False), (
        f"the refused update changed the profile: {got['brandProfileName']!r}, "
        f"{got['deletionProtectionEnabled']!r}"
    )

    renamed = ctx.unique_name("sim2real-behav-eum-updnone-r-")
    eum.update_brand_profile(brandProfileId=bpid, brandProfileName=renamed)
    assert eum.get_brand_profile(brandProfileId=bpid)["brandProfileName"] == renamed, (
        "positive control: a named update must apply"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
