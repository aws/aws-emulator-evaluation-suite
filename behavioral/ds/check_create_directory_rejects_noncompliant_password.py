"""create-directory-rejects-noncompliant-password."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-directory-rejects-noncompliant-password"
GROUP = 'input-validation'
SERVICES = ['ds']

# The Password member of CreateDirectoryRequest carries a modeled pattern (and @sensitive):
#   ^(?=^.{8,64}$)((?=.*\d)(?=.*[A-Z])(?=.*[a-z])
#                 |(?=.*\d)(?=.*[^A-Za-z0-9\s])(?=.*[a-z])
#                 |(?=.*[^A-Za-z0-9\s])(?=.*[A-Z])(?=.*[a-z])
#                 |(?=.*\d)(?=.*[A-Z])(?=.*[^A-Za-z0-9\s]))^
# Read as a rule, the four alternations are exactly "at least three of the four character
# classes {digit, upper, lower, symbol}", length 8-64. Not "must contain a symbol" and not
# "must contain a digit" — either of those is over-strict, and each is a plausible wrong
# implementation. Every string below satisfies or violates that regex as labelled.
_VALID_NAME_SUFFIX = ".example.com"
_VALID_SHORT_NAME = "SIM2REAL"
_ABSENT_VPC = {
    "VpcId": "vpc-0123456789abcdef0",
    "SubnetIds": ["subnet-0123456789abcdef0", "subnet-0fedcba9876543210"],
}
# (label, password) — each is non-compliant for exactly one reason.
_NONCOMPLIANT = (
    ("7 characters, below the 8-character minimum", "Sim2#Re"),
    ("only two classes (lower + digit)", "sim2real99pass"),
    ("only two classes (upper + lower)", "SimRealPassword"),
)
# Three of the four classes, no symbol: the model PERMITS this. A service that demands a
# symbol is over-strict and this is what catches it.
_THREE_CLASS_PASSWORD = "Sim2RealPassword"
# All four classes.
_COMPLIANT_PASSWORD = "Sim2Real#Pass99"
# The modeled pattern as ds quotes it in a validation refusal.
_PASSWORD_PATTERN = (
    r"(?=^.{8,64}$)((?=.*\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[^A-Za-z0-9\s])(?=.*[a-z])"
    r"|(?=.*[^A-Za-z0-9\s])(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[A-Z])(?=.*[^A-Za-z0-9\s]))^.*"
)
# Password is @sensitive, so the value is elided ("Value at", not "Value '<value>' at").
_PASSWORD_REFUSAL = (
    "1 validation error detected: Value at 'password' failed to satisfy constraint: "
    f"Member must satisfy regular expression pattern: {_PASSWORD_PATTERN}"
)


# ===== helpers =====
def _directory_gone(ds, directory_id) -> bool:
    """True once DescribeDirectories reports the directory id as nonexistent."""
    try:
        ds.describe_directories(DirectoryIds=[directory_id])
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") == "EntityDoesNotExistException"
    return False


def _poll(fn, pred, *, timeout_s: float, interval_s: float = 15.0):
    """Poll fn() until pred(result) is true or the deadline passes. Returns the last result."""
    deadline = time.monotonic() + timeout_s
    while True:
        result = fn()
        if pred(result):
            return result
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)


def _create_refused(ctx, operation, kwargs):
    """operation(**kwargs) expecting refusal; return (code, message, request_id). An unexpected
    acceptance raises, after registering a delete-and-poll-to-gone cleanup so no billable
    directory can leak.

    ThrottlingException is retried rather than returned: ds rate-limits back-to-back directory
    creates hard enough that a run of these legs with no pacing gets throttled instead of
    validated, which says nothing about the password rule under test. Only a transient fault
    is retried; every modelled refusal is returned to the caller on the first attempt.
    """
    ds = ctx.client("ds")
    attempts = 6
    for attempt in range(attempts):
        try:
            created = operation(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            if code in ("ThrottlingException", "TooManyRequestsException") and attempt + 1 < attempts:
                time.sleep(5.0 * (attempt + 1))
                continue
            request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
            return code, err.get("Message") or "", request_id
        break
    else:  # pragma: no cover - the loop above always breaks or returns
        raise AssertionError("ds kept throttling CreateDirectory; no verdict on the password rule")

    directory_id = created.get("DirectoryId")
    if directory_id:
        def _reap(did=directory_id):
            try:
                ds.delete_directory(DirectoryId=did)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "DirectoryDoesNotExistException",
                    "EntityDoesNotExistException",
                ):
                    raise
                return
            # Bounded by the 1800 s cleanup budget; a directory still present then is a leak.
            if not _poll(lambda: _directory_gone(ds, did), bool, timeout_s=1740.0, interval_s=30.0):
                raise AssertionError(f"directory {did} still exists 1740s after DeleteDirectory")

        ctx.on_cleanup(_reap)
    raise AssertionError(
        f"{kwargs.get('Name')!r} was ACCEPTED (DirectoryId={directory_id!r}); a refusal was expected"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDirectory and CreateMicrosoftAD reject passwords under 8 characters or with fewer than
    three of the four character classes with an identical ValidationException that elides the
    @sensitive value, while three- and four-class passwords clear validation (ClientException)."""
    ds = ctx.client("ds")
    base = ctx.unique_name("sim2real-behav-") + _VALID_NAME_SUFFIX

    def _attempt(password, microsoft=False):
        # Keep the sim2real- prefix leading, so a name-prefix search finds any leftover.
        name = base.replace(_VALID_NAME_SUFFIX, "-msad" + _VALID_NAME_SUFFIX) if microsoft else base
        create = ds.create_microsoft_ad if microsoft else ds.create_directory
        kwargs = dict(
            Name=name,
            ShortName=_VALID_SHORT_NAME,
            Password=password,
            VpcSettings=_ABSENT_VPC,
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        # Size is a SimpleAD/ADConnector member; MicrosoftAD is sized by Edition.
        kwargs["Edition" if microsoft else "Size"] = "Standard" if microsoft else "Small"
        return _create_refused(ctx, create, kwargs)

    def _assert_pattern_refusal(code, message, password, label, operation):
        assert code == "ValidationException", (
            f"{operation} with a Password that is {label} must be refused with "
            f"ValidationException, got {code}. "
            f"InvalidPasswordException is the wrong code here: the ds model declares it only "
            f"on ResetUserPassword"
        )
        # Exact: names the member, quotes the pattern, and interpolates no value at all, so the
        # @sensitive secret is never reflected to the caller.
        assert message == _PASSWORD_REFUSAL, (
            f"{operation} must refuse the {label} password at the validation layer with the "
            f"value elided, got {message!r}"
        )

    for label, password in _NONCOMPLIANT:
        code, message, _ = _attempt(password)
        _assert_pattern_refusal(code, message, password, label, "CreateDirectory")
        # The identical rule, enforced by a DIFFERENT operation: the constraint travels with the
        # Password shape, so an emulator cannot validate one entry point and not the other.
        ms_code, ms_message, _ = _attempt(password, microsoft=True)
        _assert_pattern_refusal(ms_code, ms_message, password, label, "CreateMicrosoftAD")
        # Byte-identical: the diagnostic carries no operation- or name-specific text, so the two
        # entry points share one validation layer rather than each having its own message.
        assert ms_message == message, (
            f"both operations must produce the same validation diagnostic for the same bad "
            f"password, got {ms_message!r} vs {message!r}"
        )

    # Not over-strict: three of the four classes with no symbol is permitted by the model, so
    # this must clear validation and fail later on the absent VPC instead.
    code, _, _ = _attempt(_THREE_CLASS_PASSWORD)
    assert code == "ClientException", (
        f"Password={_THREE_CLASS_PASSWORD!r} (upper + lower + digit, no symbol) satisfies the "
        f"modeled pattern's first alternation and must PASS validation — demanding a symbol is "
        f"over-strict — so the request must die at resource resolution with ClientException, got "
        f"{code!r}"
    )
    # The same password on CreateMicrosoftAD names the absent VPC, which is what proves the
    # request got PAST validation rather than merely failing differently.
    ms_code, ms_message, ms_request_id = _attempt(_THREE_CLASS_PASSWORD, microsoft=True)
    assert ms_code == "ClientException", (
        f"a three-class password must clear CreateMicrosoftAD's validation too, got {ms_code!r}"
    )
    assert ms_message == f"Invalid VPC ID. : RequestId: {ms_request_id}", (
        f"the surviving request must fail on the ABSENT VPC — that is what proves validation "
        f"passed — got {ms_message!r}"
    )

    # Effect absent: no directory exists under either of our names after every attempt.
    leaked = [
        d.get("DirectoryId")
        for d in ds.describe_directories().get("DirectoryDescriptions", [])
        if (d.get("Name") or "").endswith(base)
    ]
    assert not leaked, (
        f"refused CreateDirectory calls must create nothing, found {leaked}"
    )

    # Control: an all-four-class password on the same request also clears validation, so the
    # refusals above are about the Password member and not about the request as a whole.
    control, _, _ = _attempt(_COMPLIANT_PASSWORD)
    assert control == "ClientException", (
        f"a fully compliant Password must get past input validation and fail on resource "
        f"resolution instead, got {control!r}"
    )
    ms_control, ms_control_message, ms_control_request_id = _attempt(
        _COMPLIANT_PASSWORD, microsoft=True
    )
    assert ms_control == "ClientException", ms_control
    assert ms_control_message == f"Invalid VPC ID. : RequestId: {ms_control_request_id}", (
        ms_control_message
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
