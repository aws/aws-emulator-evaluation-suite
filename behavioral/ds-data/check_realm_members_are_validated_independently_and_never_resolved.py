"""realm-members-are-validated-independently-and-never-resolved."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "realm-members-are-validated-independently-and-never-resolved"
GROUP = 'directory-data-rejects'
SERVICES = ['ds-data']

_REALM_PATTERN = "([a-zA-Z0-9]+[\\\\.-])+([a-zA-Z0-9])+[.]?"
_BAD_REALM = "not a realm!"
_BAD_MEMBER_REALM = "also not a realm!"
_FOREIGN_REALM = "trusted.sim2real.example.com"

# Every ds-data operation carrying a Realm or MemberRealm member, and which ones it carries.
_REALM_BEARING = (
    ("list_users", {}, ("Realm",)),
    ("list_groups", {}, ("Realm",)),
    ("describe_user", {"SAMAccountName": "sim2real-behav-u"}, ("Realm",)),
    ("describe_group", {"SAMAccountName": "sim2real-behav-g"}, ("Realm",)),
    ("search_users", {"SearchString": "sim2real", "SearchAttributes": ["Cn"]}, ("Realm",)),
    ("search_groups", {"SearchString": "sim2real", "SearchAttributes": ["Cn"]}, ("Realm",)),
    ("list_group_members", {"SAMAccountName": "sim2real-behav-g"}, ("Realm", "MemberRealm")),
    ("list_groups_for_member", {"SAMAccountName": "sim2real-behav-u"}, ("Realm", "MemberRealm")),
    ("add_group_member", {"GroupName": "sim2real-behav-g", "MemberName": "sim2real-behav-u"},
     ("MemberRealm",)),
    ("remove_group_member", {"GroupName": "sim2real-behav-g", "MemberName": "sim2real-behav-u"},
     ("MemberRealm",)),
)


# ===== helpers =====
def _refusal(fn):
    """Call fn(); return (Code, Message, Reason) of the ClientError it must raise.

    Raises on SUCCESS rather than returning a falsy sentinel: a service that resolves a realm it
    cannot reach is a fidelity failure, not a naming difference.
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
    for candidate in (f"d-{n:010x}" for n in range(0x38DA4B96E0, 0x38DA4B96E0 + 64)):
        if candidate not in owned:
            return candidate
    raise AssertionError(f"could not find an unissued DirectoryId; owned={sorted(owned)}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Realm and MemberRealm are validated independently (one refusal naming both, memberRealm
    first) and never resolved before authorization: a well-formed foreign realm on an unreachable
    directory is answered exactly as if no realm were supplied."""
    ds = ctx.client("ds")
    dsd = ctx.client("ds-data")
    absent = _absent_directory_id(ds)

    # --- Two independent members, one message, a fixed order.
    code, message, reason = _refusal(
        lambda: dsd.list_group_members(
            DirectoryId=absent,
            SAMAccountName="sim2real-behav-g",
            Realm=_BAD_REALM,
            MemberRealm=_BAD_MEMBER_REALM,
        )
    )
    assert code == "ValidationException", (
        f"two malformed realms must be refused by the constraint layer, got {code!r}"
    )
    assert reason is None, f"a constraint refusal carries no Reason, got {reason!r}"
    assert message == (
        f"2 validation errors detected: Value '{_BAD_MEMBER_REALM}' at 'memberRealm' failed to "
        f"satisfy constraint: Member must satisfy regular expression pattern: {_REALM_PATTERN}; "
        f"Value '{_BAD_REALM}' at 'realm' failed to satisfy constraint: Member must satisfy regular "
        f"expression pattern: {_REALM_PATTERN}"
    ), (
        f"both realm members must be reported in ONE refusal -- memberRealm first -- rather than "
        f"the first fault winning, got {message!r}"
    )

    # --- Each member alone: judged on its own, and named on its own.
    code, message, reason = _refusal(
        lambda: dsd.list_group_members(
            DirectoryId=absent, SAMAccountName="sim2real-behav-g", MemberRealm=_BAD_MEMBER_REALM
        )
    )
    assert code == "ValidationException", code
    assert message == (
        f"1 validation error detected: Value '{_BAD_MEMBER_REALM}' at 'memberRealm' failed to "
        f"satisfy constraint: Member must satisfy regular expression pattern: {_REALM_PATTERN}"
    ), f"MemberRealm alone must be reported alone, got {message!r}"

    code, message, reason = _refusal(
        lambda: dsd.list_group_members(
            DirectoryId=absent, SAMAccountName="sim2real-behav-g", Realm=_BAD_REALM
        )
    )
    assert code == "ValidationException", code
    assert message == (
        f"1 validation error detected: Value '{_BAD_REALM}' at 'realm' failed to satisfy "
        f"constraint: Member must satisfy regular expression pattern: {_REALM_PATTERN}"
    ), f"Realm alone must be reported alone, got {message!r}"

    # --- Never resolved: a well-formed foreign realm changes nothing, on every operation that
    # carries one. This is the equality assertion, and it is the check's centre.
    for operation, kwargs, members in _REALM_BEARING:
        call = getattr(dsd, operation)
        bare = _refusal(lambda c=call, k=kwargs: c(DirectoryId=absent, **k))
        for member in members:
            with_realm = _refusal(
                lambda c=call, k=kwargs, m=member: c(
                    DirectoryId=absent, **{m: _FOREIGN_REALM}, **k
                )
            )
            assert with_realm[0] == "AccessDeniedException", (
                f"ds-data {operation} with a syntactically valid {member} must pass validation and "
                f"be refused by authorization, got {with_realm!r} -- a ValidationException here "
                f"means the realm is being rejected rather than merely not resolved"
            )
            assert with_realm == bare, (
                f"ds-data {operation} must answer a well-formed {member}={_FOREIGN_REALM!r} exactly "
                f"as it answers the same call with no realm at all -- the realm is not resolved "
                f"before authorization -- got {with_realm!r} vs {bare!r}"
            )
            assert _FOREIGN_REALM not in with_realm[1], (
                f"the refusal must not echo the realm it never resolved, got {with_realm[1]!r}"
            )
            assert with_realm[2] != "INVALID_REALM", (
                f"Reason INVALID_REALM is modelled but unreachable without a directory the caller "
                f"can access; {operation} reported {with_realm[2]!r}"
            )

    # --- POSITIVE CONTROL: the realm validator is live in both directions -- it accepts the shapes
    # a real trust uses (a dotted FQDN, a trailing dot, a hyphenated label) and refuses the shapes
    # it must, so the equality above is about resolution and not about a dead member.
    for legal in ("corp.example.com", "corp.example.com.", "sim2real-corp.example.com"):
        outcome = _refusal(lambda v=legal: dsd.list_users(DirectoryId=absent, Realm=v))
        assert outcome[0] == "AccessDeniedException", (
            f"Realm={legal!r} matches the modelled pattern and must pass validation, got {outcome!r}"
        )
    single_label = _refusal(lambda: dsd.list_users(DirectoryId=absent, Realm="corp"))
    assert single_label[0] == "ValidationException", (
        f"the modelled pattern requires at least one dot or hyphen separator, so a single label "
        f"must be refused -- this is what proves the validator is live -- got {single_label!r}"
    )
    assert "at 'realm'" in single_label[1], single_label[1]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
