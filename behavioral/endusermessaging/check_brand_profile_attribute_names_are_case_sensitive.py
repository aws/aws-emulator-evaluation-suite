"""brand-profile-attribute-names-are-case-sensitive."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "brand-profile-attribute-names-are-case-sensitive"
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
    """Attribute names differing only in case are distinct: City and city coexist on one
    profile, each keeping its own value.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-case-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    eum.update_brand_profile_attribute(brandProfileId=bpid, attributeName="City", attributeValue="Upper")
    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": "city", "attributeType": "TEXT", "attributeValue": "lower"}])

    upper = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName="City")
    lower = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName="city")
    assert (upper["attributeName"], upper["attributeValue"]) == ("City", "Upper"), f"City: {upper!r}"
    assert (lower["attributeName"], lower["attributeValue"]) == ("city", "lower"), f"city: {lower!r}"

    names = []
    for page in eum.get_paginator("list_brand_profile_attributes").paginate(brandProfileId=bpid):
        names.extend(a["attributeName"] for a in page["brandProfileAttributes"])
    assert names.count("City") == 1 and names.count("city") == 1, (
        f"both spellings must be listed once each, got {sorted(n for n in names if n.lower() == 'city')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
