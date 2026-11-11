"""attribute-value-union-rejects-every-member-but-string."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attribute-value-union-rejects-every-member-but-string"
GROUP = 'directory-data-rejects'
SERVICES = ['ds-data']

# AttributeValue is a four-member union in the Smithy model: S (string), N (long),
# BOOL (boolean), SS (string set). Measured, only S is accepted.
_STRING_VALUED = (
    ("telephoneNumber", {"S": "555-0100"}),
    ("description", {"S": "sim2real behavioral probe"}),
    # An attribute whose Active Directory type is an INTEGER, sent as a string: still accepted at
    # this layer, which is what makes the N rejection below a statement about the union member
    # rather than about the attribute.
    ("codePage", {"S": "0"}),
    # An attribute that does not exist in any AD schema: also accepted at this layer, so the
    # attribute NAME is not resolved before authorization either. No digits, because
    # LdapDisplayName is ^[A-Za-z*][A-Za-z-*]*$ and a digit is a CONSTRAINT fault, not a semantic one.
    ("NotARealAttribute", {"S": "x"}),
)

_NON_STRING_VALUED = (
    # (attribute, value, which union member) -- each attribute chosen so that the AD type makes
    # the union member the NATURAL encoding, which is exactly why a model-driven emulator accepts
    # it and real AWS does not.
    ("codePage", {"N": 0}, "N"),
    ("userAccountControl", {"N": 512}, "N"),
    ("accountExpires", {"N": 0}, "N"),
    ("telephoneNumber", {"N": 5550100}, "N"),
    ("otherTelephone", {"SS": ["555-0100", "555-0101"]}, "SS"),
    ("description", {"SS": ["a", "b"]}, "SS"),
    ("telephoneNumber", {"SS": ["555-0100"]}, "SS"),
    ("isDeleted", {"BOOL": True}, "BOOL"),
    ("showInAddressBook", {"BOOL": False}, "BOOL"),
    ("telephoneNumber", {"BOOL": True}, "BOOL"),
)


# ===== helpers =====
def _refusal(fn):
    """Call fn(); return (Code, Message, Reason) of the ClientError it must raise.

    Raises on SUCCESS rather than returning a falsy sentinel: an emulator accepting input real AWS
    refuses is the strongest signal here and must not read as a code mismatch.
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
    for candidate in (f"d-{n:010x}" for n in range(0x2B71E90C31, 0x2B71E90C31 + 64)):
        if candidate not in owned:
            return candidate
    raise AssertionError(f"could not find an unissued DirectoryId; owned={sorted(owned)}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """OtherAttributes values sent as N, BOOL or SS are refused with ValidationException / Reason
    INVALID_ATTRIBUTE_VALUE before authorization, while the same attribute sent as S passes to the
    IAM_AUTH layer: only the S member of the AttributeValue union is usable."""
    ds = ctx.client("ds")
    dsd = ctx.client("ds-data")
    absent = _absent_directory_id(ds)
    user = "sim2real-behav-u"
    # The authorization layer names the calling principal, so its message is built from the
    # caller's own identity as the target reports it.
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    denied_message = f"User: {caller_arn} is not authorized to access this resource"

    # --- The three unusable union members. Each must be refused by the SEMANTIC layer.
    for attribute, value, member in _NON_STRING_VALUED:
        code, message, reason = _refusal(
            lambda a=attribute, v=value: dsd.create_user(
                DirectoryId=absent, SAMAccountName=user, OtherAttributes={a: v}
            )
        )
        assert code == "ValidationException", (
            f"OtherAttributes={{{attribute!r}: {value!r}}} uses the modelled AttributeValue member "
            f"{member} and must be refused with ValidationException, got {code!r} (None means the "
            f"union member was accepted, which is what a model-driven emulator does)"
        )
        assert reason == "INVALID_ATTRIBUTE_VALUE", (
            f"the {member} member must be refused by ds-data's SEMANTIC attribute layer, which "
            f"populates Reason INVALID_ATTRIBUTE_VALUE, got {reason!r} (None means it was refused "
            f"by the Smithy-constraint layer instead, a different layer with a different grammar)"
        )
        assert message == f"Invalid value for attribute: '{attribute}'.", (
            f"the semantic layer names the offending attribute and says nothing else, got "
            f"{message!r}"
        )
        # The semantic layer's grammar is NOT the constraint layer's, so no emulator can answer
        # both with one template.
        assert "validation error" not in message and "failed to satisfy constraint" not in message, (
            f"the semantic layer must not borrow the Smithy-constraint layer's phrasing, got "
            f"{message!r}"
        )

    # --- POSITIVE CONTROL, and the ordering proof: the same attributes sent as S get PAST this
    # layer entirely and are stopped by authorization instead. Without this half, every assertion
    # above would be satisfied by a service that refuses OtherAttributes outright.
    for attribute, value in _STRING_VALUED:
        code, message, reason = _refusal(
            lambda a=attribute, v=value: dsd.create_user(
                DirectoryId=absent, SAMAccountName=user, OtherAttributes={a: v}
            )
        )
        assert code == "AccessDeniedException", (
            f"OtherAttributes={{{attribute!r}: {value!r}}} is a legal S-valued attribute and must "
            f"reach the authorization layer, got {code!r} -- if this is ValidationException then S "
            f"is being rejected too and the union is unusable rather than narrowed"
        )
        assert reason == "IAM_AUTH", (
            f"having passed attribute validation, the request must be refused by authorization "
            f"with Reason IAM_AUTH, got {reason!r}"
        )
        assert message == denied_message, (
            f"the authorization layer's refusal must be AWS's exact message, got {message!r}"
        )

    # --- The constraint layer, for contrast: a malformed attribute NAME is judged by the Smithy
    # constraint on the map's keys, reports no Reason, and -- uniquely in this API -- discloses the
    # key while redacting the value in the same string.
    code, message, reason = _refusal(
        lambda: dsd.create_user(
            DirectoryId=absent, SAMAccountName=user, OtherAttributes={"1bad": {"S": "secret-value"}}
        )
    )
    assert code == "ValidationException", (
        f"an attribute name outside LdapDisplayName's ^[A-Za-z*][A-Za-z-*]*$ must be refused with "
        f"ValidationException, got {code!r}"
    )
    assert reason is None, (
        f"the Smithy-constraint layer populates no Reason, unlike the semantic layer above, got "
        f"{reason!r}"
    )
    assert message == (
        "1 validation error detected: Value '{1bad=AttributeValue(s=*** REDACTED ***)}' at "
        "'otherAttributes' failed to satisfy constraint: Map keys must satisfy constraint: "
        "[Member must have length less than or equal to 63, Member must have length greater than "
        "or equal to 1, Member must satisfy regular expression pattern: [A-Za-z*][A-Za-z-*]*]"
    ), (
        f"the constraint layer must attribute the fault to the map's KEY and echo the entry with "
        f"the key disclosed and the @sensitive value REDACTED, got {message!r}"
    )
    assert "secret-value" not in message, (
        f"an attribute value is @sensitive and must never appear in a refusal, got {message!r}"
    )

    # --- The map's own length bound, which is a third distinct answer from the same member.
    code, message, reason = _refusal(
        lambda: dsd.create_user(
            DirectoryId=absent, SAMAccountName=user, OtherAttributes={}
        )
    )
    assert code == "ValidationException", (
        f"OtherAttributes has length min 1, so an empty map must be refused, got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value '{}' at 'otherAttributes' failed to satisfy "
        "constraint: Member must have length greater than or equal to 1"
    ), (
        f"the refusal must name the map's own length bound rather than a key or a value, got "
        f"{message!r}"
    )
    assert reason is None, f"a length violation is a constraint fault and carries no Reason: {reason!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
