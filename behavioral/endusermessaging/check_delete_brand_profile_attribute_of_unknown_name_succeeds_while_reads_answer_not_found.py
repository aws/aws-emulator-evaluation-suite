"""delete-brand-profile-attribute-of-unknown-name-succeeds-while-reads-answer-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-brand-profile-attribute-of-unknown-name-succeeds-while-reads-answer-not-found"
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
    """DeleteBrandProfileAttribute is idempotent: an attribute name the profile never held
    deletes successfully, while Get and Update of that name answer ResourceNotFoundException.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-delidem-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    attr = "Never Created"
    deleted = eum.delete_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)
    assert (deleted["brandProfileId"], deleted["attributeName"]) == (bpid, attr), (
        f"delete answered {deleted['brandProfileId']!r}, {deleted['attributeName']!r}"
    )

    expected = 'Resource not found - ResourceType="brand-profile-attribute"'
    for op, call in (
        ("GetBrandProfileAttribute",
         lambda: eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr)),
        ("UpdateBrandProfileAttribute",
         lambda: eum.update_brand_profile_attribute(brandProfileId=bpid, attributeName=attr,
                                                    attributeValue="x")),
    ):
        try:
            call()
        except ClientError as exc:
            err = exc.response
        else:
            raise AssertionError(f"{op} on a name the profile never held succeeded")
        assert (err["Error"]["Code"], err["Error"]["Message"]) == ("ResourceNotFoundException", expected), (
            f"{op}: got {err['Error']['Code']}: {err['Error']['Message']!r}"
        )
        assert (err.get("resourceId"), err.get("resourceType")) == (attr, "brand-profile-attribute"), (
            f"{op}: resourceId/resourceType {err.get('resourceId')!r}, {err.get('resourceType')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
