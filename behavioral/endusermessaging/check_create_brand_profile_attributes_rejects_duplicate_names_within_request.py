"""create-brand-profile-attributes-rejects-duplicate-names-within-request."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-brand-profile-attributes-rejects-duplicate-names-within-request"
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
    """A batch naming the same attribute twice is refused with ValidationException pointing at
    the second entry, and neither entry is created.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-batchdup-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    attr = "Repeated Note"
    try:
        eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
            {"attributeName": attr, "attributeType": "TEXT", "attributeValue": "a"},
            {"attributeName": attr, "attributeType": "TEXT", "attributeValue": "b"},
        ])
    except ClientError as exc:
        err, fields = exc.response["Error"], exc.response.get("fieldList")
    else:
        raise AssertionError("expected the batch with a repeated name to be refused")
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err!r}"
    assert err["Message"] == f"Duplicate attribute name: '{attr}'", f"unexpected message {err['Message']!r}"
    assert fields == [{"path": "/attributes/1/attributeName",
                       "message": f"Duplicate attribute name: '{attr}'"}], f"fieldList {fields!r}"

    code, message = _error(lambda: eum.get_brand_profile_attribute(brandProfileId=bpid, attributeName=attr))
    assert code == "ResourceNotFoundException", f"neither entry may be created, got {code}: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
