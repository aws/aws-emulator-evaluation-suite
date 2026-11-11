"""delete-brand-profile-cascades-to-attributes."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-brand-profile-cascades-to-attributes"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting a brand profile also removes its custom attributes: a later
    GetBrandProfileAttribute on the deleted profile answers ResourceNotFoundException.
    """
    eum = ctx.client("endusermessaging")
    bp_name = ctx.unique_name("sim2real-behav-eum-cascade-")
    attr_name = ctx.unique_name("sim2real-behav-eum-attr-")

    bpid = eum.create_brand_profile(brandProfileName=bp_name)["brandProfileId"]
    eum.create_brand_profile_attributes(
        brandProfileId=bpid,
        attributes=[{"attributeName": attr_name, "attributeType": "TEXT", "attributeValue": "v"}],
    )

    got = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr_name)
    assert got["attributeValue"] == "v", f"expected the attribute to hold 'v', got {got['attributeValue']!r}"

    eum.delete_brand_profile(brandProfileId=bpid)

    code, message = _error(
        lambda: eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr_name)
    )
    assert code == "ResourceNotFoundException", (
        f"expected the attribute to be gone with its profile, got {code}: {message!r}"
    )
    assert message == f'Resource not found - ResourceType="brand-profile" ResourceId="{bpid}"', (
        f"unexpected message {message!r}"
    )

    code, message = _error(lambda: eum.get_brand_profile(brandProfileId=bpid))
    assert code == "ResourceNotFoundException", (
        f"expected the profile itself to be gone, got {code}: {message!r}"
    )
    assert message == f'Resource not found - ResourceType="brand-profile" ResourceId="{bpid}"', (
        f"unexpected message {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
