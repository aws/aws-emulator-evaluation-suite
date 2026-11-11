"""create-brand-profile-attributes-rejects-duplicate-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-brand-profile-attributes-rejects-duplicate-name"
GROUP = 'brand-profile-attributes'
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
    """A second CreateBrandProfileAttributes call reusing an attribute name is refused with
    ConflictException, and the attribute's original value is left unchanged.
    """
    eum = ctx.client("endusermessaging")
    bp_name = ctx.unique_name("sim2real-behav-eum-attrdup-")
    attr_name = ctx.unique_name("sim2real-behav-eum-attr-")

    bpid = eum.create_brand_profile(brandProfileName=bp_name)["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))

    eum.create_brand_profile_attributes(
        brandProfileId=bpid,
        attributes=[{"attributeName": attr_name, "attributeType": "TEXT", "attributeValue": "first"}],
    )

    code, message = _error(lambda: eum.create_brand_profile_attributes(
        brandProfileId=bpid,
        attributes=[{"attributeName": attr_name, "attributeType": "TEXT", "attributeValue": "second"}],
    ))
    assert code == "ConflictException", f"expected ConflictException on a duplicate name, got {code}: {message!r}"
    assert message == (
        'Conflict occurred - Reason="RESOURCE_ALREADY_EXISTS" ResourceType="brand-profile-attribute"'
    ), f"unexpected message {message!r}"

    got = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr_name)
    assert got["attributeValue"] == "first", (
        f"the refused duplicate create changed the attribute value to {got['attributeValue']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
