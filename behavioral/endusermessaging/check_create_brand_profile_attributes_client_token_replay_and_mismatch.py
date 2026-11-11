"""create-brand-profile-attributes-client-token-replay-and-mismatch."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-brand-profile-attributes-client-token-replay-and-mismatch"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A replay of CreateBrandProfileAttributes with the same client token and body succeeds
    without a conflict; the token with a different body is refused and creates nothing.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-attrtok-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    token = ctx.unique_name("sim2real-behav-eum-tok-")
    first = [{"attributeName": "Token Note", "attributeType": "TEXT", "attributeValue": "a"}]
    eum.create_brand_profile_attributes(brandProfileId=bpid, clientToken=token, attributes=first)
    replay = eum.create_brand_profile_attributes(brandProfileId=bpid, clientToken=token, attributes=first)
    assert replay["attributes"] == [{"attributeName": "Token Note", "attributeType": "TEXT"}], (
        f"the replay must answer the first call's result, got {replay['attributes']!r}"
    )

    code, message = _error(lambda: eum.create_brand_profile_attributes(
        brandProfileId=bpid, clientToken=token,
        attributes=[{"attributeName": "Other Note", "attributeType": "TEXT", "attributeValue": "a"}]))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "The idempotency token and parameters presented do not match", (
        f"unexpected message {message!r}"
    )
    code, _ = _error(lambda: eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName="Other Note"))
    assert code == "ResourceNotFoundException", f"the mismatched request created its attribute: {code}"

    names = []
    for page in eum.get_paginator("list_brand_profile_attributes").paginate(brandProfileId=bpid):
        names.extend(a["attributeName"] for a in page["brandProfileAttributes"])
    assert names.count("Token Note") == 1, f"Token Note must exist once, got {names.count('Token Note')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
