"""sensitive-member-values-are-withheld-when-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sensitive-member-values-are-withheld-when-rejected"
GROUP = 'directory-data-rejected'
SERVICES = ['ds-data']

# The offending value is echoed for a member the model does NOT mark @sensitive.
# (label, request kwargs, member name as the service spells it, the value it must echo)
_ECHOED = (
    ("directoryId pattern", {"DirectoryId": "not-a-directory-id",
                             "SAMAccountName": "sim2real-behav-u"},
     "directoryId", "not-a-directory-id"),
    ("sAMAccountName pattern", {"SAMAccountName": "sim2real:behav"},
     "sAMAccountName", "sim2real:behav"),
    ("sAMAccountName length", {"SAMAccountName": "s" * 21},
     "sAMAccountName", "s" * 21),
)
# The offending value is WITHHELD for a member the model marks @sensitive. Same error code, same
# grammar, one clause deleted.
_WITHHELD = (
    ("searchString length", "search_users",
     {"SearchString": "s" * 65, "SearchAttributes": ["Cn"]}, "searchString", 64),
    ("emailAddress length", "create_user",
     {"SAMAccountName": "sim2real-behav-u", "EmailAddress": "e" * 257}, "emailAddress", 256),
    ("givenName length", "create_user",
     {"SAMAccountName": "sim2real-behav-u", "GivenName": "g" * 65}, "givenName", 64),
    ("surname length", "create_user",
     {"SAMAccountName": "sim2real-behav-u", "Surname": "s" * 65}, "surname", 64),
)


# ===== helpers =====
def _refusal(fn):
    """Call fn(); return (Code, Message, Reason) of the ClientError it must raise.

    Raises on SUCCESS rather than returning a falsy sentinel, so an emulator accepting input real
    AWS refuses cannot read as a code mismatch.
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
    for candidate in (f"d-{n:010x}" for n in range(0x7C31D0AE55, 0x7C31D0AE55 + 64)):
        if candidate not in owned:
            return candidate
    raise AssertionError(f"could not find an unissued DirectoryId; owned={sorted(owned)}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ds-data validation refusals withhold the value of @sensitive members ("Value at '<member>'")
    while echoing non-sensitive ones and still stating the violated constraint, per member within
    one message and inside structures as a REDACTED marker."""
    ds = ctx.client("ds")
    dsd = ctx.client("ds-data")
    absent = _absent_directory_id(ds)

    # --- Members that are not @sensitive: the value is echoed.
    for label, kwargs, member, value in _ECHOED:
        request = {"DirectoryId": absent, **kwargs}
        code, message, reason = _refusal(lambda r=request: dsd.describe_user(**r))
        assert code == "ValidationException", (
            f"{label} must be refused with ValidationException, got {code!r}"
        )
        assert reason is None, (
            f"a Smithy-constraint refusal carries no Reason discriminator, got {reason!r} for "
            f"{label}"
        )
        assert f"Value '{value}' at '{member}'" in message, (
            f"{member} is not @sensitive, so its offending value must be echoed as "
            f"\"Value '{value}' at '{member}'\", got {message!r}"
        )

    # --- Members that ARE @sensitive: the same grammar with the value clause deleted.
    for label, operation, kwargs, member, bound in _WITHHELD:
        request = {"DirectoryId": absent, **kwargs}
        call = getattr(dsd, operation)
        code, message, reason = _refusal(lambda c=call, r=request: c(**r))
        assert code == "ValidationException", (
            f"{label} must be refused with ValidationException, got {code!r}"
        )
        assert reason is None, (
            f"a Smithy-constraint refusal carries no Reason discriminator, got {reason!r} for "
            f"{label}"
        )
        assert message == (
            f"1 validation error detected: Value at '{member}' failed to satisfy constraint: "
            f"Member must have length less than or equal to {bound}"
        ), (
            f"{member} is @sensitive, so the refusal must name the member and the bound it "
            f"violated while WITHHOLDING the value -- 'Value at' rather than \"Value '...' at\" -- "
            f"got {message!r}"
        )
        # The value really is absent, not merely truncated or hashed.
        offending = next(v for v in kwargs.values() if isinstance(v, str) and len(v) > bound)
        assert offending not in message, (
            f"the @sensitive value leaked into the refusal for {label}: {message!r}"
        )

    # --- The decision is per MEMBER, inside one message: a request that violates a sensitive and a
    # non-sensitive constraint at once echoes exactly one of the two values.
    code, message, reason = _refusal(
        lambda: dsd.create_user(
            DirectoryId=absent, SAMAccountName="s" * 21, GivenName="g" * 65
        )
    )
    assert code == "ValidationException", code
    assert message.startswith("2 validation errors detected: "), (
        f"both violations must be reported in one refusal, got {message!r}"
    )
    assert f"Value '{'s' * 21}' at 'sAMAccountName'" in message, (
        f"the non-sensitive member's value must still be echoed alongside a withheld one, got "
        f"{message!r}"
    )
    assert "Value at 'givenName'" in message, (
        f"the @sensitive member in the same message must be reported without its value, got "
        f"{message!r}"
    )
    assert "g" * 65 not in message, (
        f"the @sensitive value leaked from a mixed refusal: {message!r}"
    )

    # --- Inside a structure the trait is honoured by an explicit marker rather than by a deleted
    # clause, so the two mechanisms cannot be satisfied by one rule.
    code, message, reason = _refusal(
        lambda: dsd.create_user(
            DirectoryId=absent,
            SAMAccountName="sim2real-behav-u",
            OtherAttributes={"1bad": {"S": "sim2real-secret-attribute-value"}},
        )
    )
    assert code == "ValidationException", code
    assert "AttributeValue(s=*** REDACTED ***)" in message, (
        f"a @sensitive value nested in a structure must be replaced by an explicit redaction "
        f"marker, got {message!r}"
    )
    assert "sim2real-secret-attribute-value" not in message, (
        f"the nested @sensitive value leaked: {message!r}"
    )
    assert "'{1bad=" in message, (
        f"the map KEY is not @sensitive and must still be echoed in the same string, got "
        f"{message!r}"
    )

    # --- POSITIVE CONTROL: with legal values for exactly those @sensitive members, the identical
    # requests pass validation and are stopped by authorization instead. Without this the
    # assertions above would be satisfied by a service that refuses these members outright.
    for operation, kwargs in (
        ("search_users", {"SearchString": "s" * 64, "SearchAttributes": ["Cn"]}),
        ("create_user", {"SAMAccountName": "sim2real-behav-u", "EmailAddress": "e" * 256}),
        ("create_user", {"SAMAccountName": "sim2real-behav-u", "GivenName": "g" * 64,
                         "Surname": "s" * 64}),
    ):
        call = getattr(dsd, operation)
        code, message, reason = _refusal(
            lambda c=call, k=kwargs: c(DirectoryId=absent, **k)
        )
        assert code == "AccessDeniedException", (
            f"{operation} with @sensitive members exactly at their bounds must pass validation and "
            f"reach authorization, got {code!r} -- a ValidationException here means the bound is "
            f"not where the model says it is"
        )
        assert reason == "IAM_AUTH", (
            f"the surviving request must be refused by authorization, got Reason {reason!r}"
        )
        assert "failed to satisfy constraint" not in message, message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
