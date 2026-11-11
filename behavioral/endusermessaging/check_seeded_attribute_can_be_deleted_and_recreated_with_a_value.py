"""seeded-attribute-can-be-deleted-and-recreated-with-a-value."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "seeded-attribute-can-be-deleted-and-recreated-with-a-value"
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
    """A template attribute a new profile is seeded with can be deleted and then created again
    under the same name, now holding the value the caller supplies.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-seed-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    seeded = []
    for page in eum.get_paginator("list_brand_profile_attributes").paginate(brandProfileId=bpid):
        seeded.extend(a["attributeName"] for a in page["brandProfileAttributes"])
    assert "City" in seeded, f"expected the seeded template to hold City, got {sorted(seeded)!r}"

    eum.delete_brand_profile_attribute(brandProfileId=bpid, attributeName="City")
    code, message = _error(lambda: eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName="City"))
    assert code == "ResourceNotFoundException", f"City must be gone after delete, got {code}: {message!r}"
    assert message == 'Resource not found - ResourceType="brand-profile-attribute"', (
        f"unexpected message {message!r}"
    )

    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": "City", "attributeType": "TEXT", "attributeValue": "Anytown"}])
    got = eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName="City")
    assert (got["attributeType"], got["attributeValue"]) == ("TEXT", "Anytown"), (
        f"recreated City: {got['attributeType']!r}, {got.get('attributeValue')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
