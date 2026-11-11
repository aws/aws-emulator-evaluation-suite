"""pagination-token-is-not-parsed-before-authorization-rejects."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pagination-token-is-not-parsed-before-authorization-rejects"
GROUP = 'directory-data-rejects'
SERVICES = ['ds-data']

# Every @paginated ds-data operation, as (attribute, kwargs-without-DirectoryId-or-NextToken).
_PAGINATED = (
    ("list_users", {}),
    ("list_groups", {}),
    ("list_group_members", {"SAMAccountName": "sim2real-behav-g"}),
    ("list_groups_for_member", {"SAMAccountName": "sim2real-behav-u"}),
    ("search_users", {"SearchString": "sim2real", "SearchAttributes": ["Cn"]}),
    ("search_groups", {"SearchString": "sim2real", "SearchAttributes": ["Cn"]}),
)

_GARBAGE_TOKEN = "sim2real-behav-not-a-real-pagination-token"


# ===== helpers =====
def _refusal(fn):
    """Call fn(); return (Code, Message, Reason) of the ClientError it must raise.

    Raises on SUCCESS rather than returning a falsy sentinel: a service that accepts a fabricated
    pagination token is a fidelity failure, not a naming difference.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {}) or {}
        return error.get("Code"), error.get("Message") or "", exc.response.get("Reason")
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED with {result!r}")


def _absent_directory_id(ds) -> str:
    """A DirectoryId matching ^d-[0-9a-f]{10}$ that this account demonstrably does not hold."""
    owned = set()
    token = None
    while True:
        page = ds.describe_directories(**({"NextToken": token} if token else {}))
        for description in page.get("DirectoryDescriptions") or []:
            owned.add(description.get("DirectoryId"))
        token = page.get("NextToken")
        if not token:
            break
    for candidate in (f"d-{n:010x}" for n in range(0x1A05C3F7B8, 0x1A05C3F7B8 + 64)):
        if candidate not in owned:
            return candidate
    raise AssertionError(f"could not find an unissued DirectoryId; owned={sorted(owned)}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A fabricated NextToken on an unreachable directory is refused by authorization
    (AccessDeniedException / IAM_AUTH) exactly as if absent, never INVALID_NEXT_TOKEN, while its
    length bound is still enforced and the ds control plane does parse the same token."""
    ds = ctx.client("ds")
    dsd = ctx.client("ds-data")
    absent = _absent_directory_id(ds)

    # --- Layer 2 wins over the token, on every paginated operation.
    with_token = {}
    without_token = {}
    for operation, kwargs in _PAGINATED:
        call = getattr(dsd, operation)
        with_token[operation] = _refusal(
            lambda c=call, k=kwargs: c(DirectoryId=absent, NextToken=_GARBAGE_TOKEN, **k)
        )
        without_token[operation] = _refusal(lambda c=call, k=kwargs: c(DirectoryId=absent, **k))

    for operation, (code, message, reason) in sorted(with_token.items()):
        assert code == "AccessDeniedException", (
            f"ds-data {operation} with a fabricated NextToken on an unreachable directory must be "
            f"refused by AUTHORIZATION, got {code!r} -- a ValidationException here means the token "
            f"was parsed first, which is the model-driven ordering and not what real AWS does"
        )
        assert reason == "IAM_AUTH", (
            f"{operation} must report the authorization Reason, not a pagination one, got {reason!r}"
        )
        assert reason != "INVALID_NEXT_TOKEN", reason
        assert "NextToken" not in message and _GARBAGE_TOKEN not in message, (
            f"the refusal must not mention a token it never examined, got {message!r}"
        )
        assert with_token[operation] == without_token[operation], (
            f"ds-data {operation} must answer identically with and without the fabricated token -- "
            f"the token is not part of the decision -- got {with_token[operation]!r} vs "
            f"{without_token[operation]!r}"
        )

    # --- Layer 1 wins over layer 2, and the token is not judged there either: exactly ONE
    # validation error, and it is the DirectoryId.
    code, message, reason = _refusal(
        lambda: dsd.list_users(DirectoryId="zzz", NextToken=_GARBAGE_TOKEN)
    )
    assert code == "ValidationException", (
        f"a malformed DirectoryId must be refused by the constraint layer even when the request "
        f"also carries a fabricated token, got {code!r}"
    )
    assert reason is None, f"a constraint refusal carries no Reason, got {reason!r}"
    assert message == (
        "1 validation error detected: Value 'zzz' at 'directoryId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: d-[0-9a-f]{10}"
    ), (
        f"the constraint layer must report ONE fault -- the DirectoryId -- and not judge the "
        f"NextToken alongside it, got {message!r}"
    )

    # And a second, different constraint fault still reports one error, so "1" above is about the
    # token being unjudged rather than about this particular member.
    code, message, reason = _refusal(
        lambda: dsd.list_users(DirectoryId=absent, MaxResults=999, NextToken=_GARBAGE_TOKEN)
    )
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value '999' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 250"
    ), (
        f"a bad MaxResults alongside a fabricated token must also report exactly one fault, got "
        f"{message!r}"
    )

    # --- POSITIVE CONTROL, cross-API: the very same fabricated token IS parsed and rejected by ds,
    # so it is not a token every AWS API ignores -- ds-data specifically never reaches its parser.
    code, message, reason = _refusal(
        lambda: ds.describe_directories(NextToken=_GARBAGE_TOKEN)
    )
    assert code == "InvalidNextTokenException", (
        f"the ds control plane must parse and reject the same fabricated token, got {code!r} -- if "
        f"this passes, the token is simply valid everywhere and the ordering claim above is vacuous"
    )
    assert "NextToken" in message, (
        f"ds must attribute the fault to the token, got {message!r}"
    )

    # --- POSITIVE CONTROL, in-API and on the token itself: NextToken IS a constrained shape and
    # its constraint IS enforced -- one character over its length bound is a ValidationException
    # naming nextToken. So the token's immunity above is specifically about PARSING, not about a
    # missing validator, and this is the sharpest form the ordering claim can take.
    code, message, reason = _refusal(
        lambda: dsd.list_users(DirectoryId=absent, NextToken="t" * 6145)
    )
    assert code == "ValidationException", (
        f"a NextToken one character past its length bound must be refused by the constraint layer, "
        f"got {code!r} -- if this is AccessDeniedException the token has no validator at all and "
        f"the claim above is weaker than stated"
    )
    assert message == (
        "1 validation error detected: Value at 'nextToken' failed to satisfy constraint: "
        "Member must have length less than or equal to 6144"
    ), (
        f"the token's length fault must name nextToken and withhold the value (NextToken is "
        f"@sensitive), got {message!r}"
    )
    # ...and exactly at the bound it passes validation and is once again ignored, refused by
    # authorization with the same envelope as the fabricated short token.
    at_bound = _refusal(lambda: dsd.list_users(DirectoryId=absent, NextToken="t" * 6144))
    assert at_bound == with_token["list_users"], (
        f"a legal-length unparseable token must be answered exactly like the short fabricated one, "
        f"got {at_bound!r} vs {with_token['list_users']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
