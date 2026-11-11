"""sam-account-name-shape-differs-by-operation-family."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-account-name-shape-differs-by-operation-family"
GROUP = 'directory-data-rejects'
SERVICES = ['ds-data']

# The one wire member `SAMAccountName` is targeted at THREE different Smithy shapes depending on
# the operation, and the request member `MemberName` at a fourth position of the same shape:
#   UserName    length 1..20, pattern ^[\w\-.]+$          -- the seven /Users/* operations
#   GroupName   length 1..64, pattern ^[^:;|=+"*?<>/\\,\[\]@]+$ -- the six /Groups/* operations
#   MemberName  length 1..63, same wide pattern as GroupName    -- ListGroupsForMember
_USER_OPERATION = "describe_user"
_GROUP_OPERATION = "describe_group"
_MEMBER_OPERATION = "list_groups_for_member"

# A space is inside GroupName/MemberName's charset and outside UserName's, so it separates the two
# patterns without touching any length bound.
_SPACED = "sim2real behav"


# ===== helpers =====
def _refusal(fn):
    """Call fn(); return (Code, Message, Reason) of the ClientError it must raise.

    Raises on SUCCESS rather than returning a falsy sentinel, so an emulator that accepts a name
    real AWS refuses cannot read as a code mismatch.
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
    for candidate in (f"d-{n:010x}" for n in range(0x63BE20D149, 0x63BE20D149 + 64)):
        if candidate not in owned:
            return candidate
    raise AssertionError(f"could not find an unissued DirectoryId; owned={sorted(owned)}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SAMAccountName is validated against three operation-specific shapes (users max 20 with a
    narrow charset, groups max 64 wide, ListGroupsForMember max 63), and AddGroupMember enforces 64
    and 63 on two members of one request."""
    ds = ctx.client("ds")
    dsd = ctx.client("ds-data")
    absent = _absent_directory_id(ds)

    user_op = getattr(dsd, _USER_OPERATION)
    group_op = getattr(dsd, _GROUP_OPERATION)
    member_op = getattr(dsd, _MEMBER_OPERATION)

    # --- UserName: max 20, narrow charset.
    at_20 = _refusal(lambda: user_op(DirectoryId=absent, SAMAccountName="u" * 20))
    assert at_20[0] == "AccessDeniedException", (
        f"a 20-character SAMAccountName is legal for a user operation and must pass validation, got "
        f"{at_20!r}"
    )
    code, message, reason = _refusal(
        lambda: user_op(DirectoryId=absent, SAMAccountName="u" * 21)
    )
    assert code == "ValidationException", (
        f"a 21-character SAMAccountName must be refused on a user operation, got {code!r}"
    )
    assert message == (
        f"1 validation error detected: Value '{'u' * 21}' at 'sAMAccountName' failed to satisfy "
        f"constraint: Member must have length less than or equal to 20"
    ), f"the refusal must name UserName's own bound of 20, got {message!r}"

    code, message, reason = _refusal(
        lambda: user_op(DirectoryId=absent, SAMAccountName=_SPACED)
    )
    assert code == "ValidationException", (
        f"a space is outside UserName's ^[\\w\\-.]+$ and must be refused on a user operation, got "
        f"{code!r}"
    )
    assert message == (
        f"1 validation error detected: Value '{_SPACED}' at 'sAMAccountName' failed to satisfy "
        f"constraint: Member must satisfy regular expression pattern: [\\w\\-.]+"
    ), f"the refusal must quote UserName's pattern, got {message!r}"

    # --- GroupName: max 64, wide charset. THE CONTRAST: the two values just refused are legal here.
    for label, value in (("21 characters", "g" * 21), ("a space", _SPACED),
                         ("64 characters", "g" * 64)):
        outcome = _refusal(lambda v=value: group_op(DirectoryId=absent, SAMAccountName=v))
        assert outcome[0] == "AccessDeniedException", (
            f"SAMAccountName with {label} is legal for a GROUP operation -- GroupName is max 64 "
            f"with a wide charset -- and must pass validation to reach authorization, got "
            f"{outcome!r} (a ValidationException here means one shared name validator is being "
            f"applied to both families, which is the defect this check exists to catch)"
        )
    assert at_20 == _refusal(
        lambda: group_op(DirectoryId=absent, SAMAccountName="g" * 21)
    ), "once validation is passed the two families must be refused identically by authorization"

    code, message, reason = _refusal(
        lambda: group_op(DirectoryId=absent, SAMAccountName="g" * 65)
    )
    assert code == "ValidationException", (
        f"a 65-character SAMAccountName must be refused on a group operation, got {code!r}"
    )
    assert message == (
        f"1 validation error detected: Value '{'g' * 65}' at 'sAMAccountName' failed to satisfy "
        f"constraint: Member must have length less than or equal to 64"
    ), f"the refusal must name GroupName's own bound of 64, not UserName's 20, got {message!r}"

    # --- MemberName: max 63, reached through the member still spelled SAMAccountName.
    at_63 = _refusal(lambda: member_op(DirectoryId=absent, SAMAccountName="m" * 63))
    assert at_63[0] == "AccessDeniedException", (
        f"a 63-character SAMAccountName is legal for ListGroupsForMember and must pass validation, "
        f"got {at_63!r}"
    )
    code, message, reason = _refusal(
        lambda: member_op(DirectoryId=absent, SAMAccountName="m" * 64)
    )
    assert code == "ValidationException", (
        f"a 64-character SAMAccountName must be refused on ListGroupsForMember, got {code!r}"
    )
    assert message == (
        f"1 validation error detected: Value '{'m' * 64}' at 'sAMAccountName' failed to satisfy "
        f"constraint: Member must have length less than or equal to 63"
    ), (
        f"ListGroupsForMember's SAMAccountName is a MemberName, so its bound is 63 -- one below the "
        f"group operations' 64 and forty-three above the user operations' 20 -- got {message!r}"
    )
    # THE THREE-CEILING CLAIM: 64 characters is legal for a group, illegal for a member, and both
    # are reported under the same member name.
    assert _refusal(lambda: group_op(DirectoryId=absent, SAMAccountName="m" * 64))[0] == (
        "AccessDeniedException"
    ), (
        "64 characters must be legal on a group operation and illegal on ListGroupsForMember; if "
        "both refuse it, the two shapes have been collapsed into one"
    )

    # --- AddGroupMember: two of the three ceilings, in one request.
    both_legal = _refusal(
        lambda: dsd.add_group_member(
            DirectoryId=absent, GroupName="g" * 64, MemberName="m" * 63
        )
    )
    assert both_legal[0] == "AccessDeniedException", (
        f"GroupName at 64 and MemberName at 63 are both legal and the request must reach "
        f"authorization, got {both_legal!r}"
    )
    code, message, reason = _refusal(
        lambda: dsd.add_group_member(
            DirectoryId=absent, GroupName="g" * 64, MemberName="m" * 64
        )
    )
    assert code == "ValidationException", code
    assert message == (
        f"1 validation error detected: Value '{'m' * 64}' at 'memberName' failed to satisfy "
        f"constraint: Member must have length less than or equal to 63"
    ), (
        f"only MemberName is over its bound, so exactly one fault must be reported and it must name "
        f"'memberName' and 63 while leaving the 64-character GroupName alone, got {message!r}"
    )
    code, message, reason = _refusal(
        lambda: dsd.add_group_member(
            DirectoryId=absent, GroupName="g" * 65, MemberName="m" * 64
        )
    )
    assert code == "ValidationException", code
    assert message == (
        f"2 validation errors detected: Value '{'g' * 65}' at 'groupName' failed to satisfy "
        f"constraint: Member must have length less than or equal to 64; Value '{'m' * 64}' at "
        f"'memberName' failed to satisfy constraint: Member must have length less than or equal "
        f"to 63"
    ), (
        f"both members must be reported in one refusal, each against its OWN bound -- 64 for the "
        f"group, 63 for the member -- got {message!r}"
    )

    # --- POSITIVE CONTROL: the ds control plane is healthy, so every refusal above is ds-data's.
    limits = ds.get_directory_limits()
    assert isinstance(limits.get("DirectoryLimits"), dict), (
        f"ds GetDirectoryLimits must still succeed, got {limits!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
