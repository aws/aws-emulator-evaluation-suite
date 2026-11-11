"""list-brand-profile-attributes-pages-cover-every-attribute-once."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-brand-profile-attributes-pages-cover-every-attribute-once"
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
    """ListBrandProfileAttributes paged ten at a time returns every seeded and custom attribute
    exactly once, and a forged nextToken is refused with ValidationException.
    """
    eum = ctx.client("endusermessaging")
    bpid = eum.create_brand_profile(
        brandProfileName=ctx.unique_name("sim2real-behav-eum-attrpage-")
    )["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    custom = [f"Custom Note {i}" for i in range(3)]
    eum.create_brand_profile_attributes(brandProfileId=bpid, attributes=[
        {"attributeName": n, "attributeType": "TEXT", "attributeValue": "v"} for n in custom])
    whole = eum.list_brand_profile_attributes(brandProfileId=bpid, maxResults=100)
    assert "nextToken" not in whole, "100 per page must hold every attribute of the profile"
    expected = sorted(a["attributeName"] for a in whole["brandProfileAttributes"])
    assert set(custom) <= set(expected), f"custom attributes missing from {expected!r}"

    seen, pages, token = [], 0, None
    while True:
        kwargs = {"brandProfileId": bpid, "maxResults": 10}
        if token:
            kwargs["nextToken"] = token
        page = eum.list_brand_profile_attributes(**kwargs)
        assert len(page["brandProfileAttributes"]) <= 10, f"page {pages} exceeds maxResults"
        seen.extend(a["attributeName"] for a in page["brandProfileAttributes"])
        pages += 1
        token = page.get("nextToken")
        if not token or pages > 20:
            break
    assert token is None, "pagination did not end"
    assert sorted(seen) == expected, f"pages returned {len(seen)} names, expected {len(expected)}"
    assert len(seen) == len(set(seen)), "an attribute appeared on two pages"

    code, message = _error(lambda: eum.list_brand_profile_attributes(brandProfileId=bpid,
                                                                     nextToken="forged-token"))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "Invalid or expired pagination token", f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
