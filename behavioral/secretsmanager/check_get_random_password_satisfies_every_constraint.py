"""get-random-password-satisfies-every-constraint."""
from __future__ import annotations

import string

from botocore.exceptions import ClientError

from behavioral_harness import tags

# GetRandomPassword creates no resource, so no teardown helper is needed.

_PUNCTUATION = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

# Independent draws used to decide whether the space character is in the alphabet at all. See the
# probability argument at its use site.
_SPACE_DRAWS = 12


def _error(fn):
    """Call fn(); return the botocore Error dict. An unexpected SUCCESS raises, so a target
    accepting what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _classes(pwd):
    """Which character classes are actually present in the generated password."""
    return {
        "lower": any(c in string.ascii_lowercase for c in pwd),
        "upper": any(c in string.ascii_uppercase for c in pwd),
        "digit": any(c in string.digits for c in pwd),
        "punct": any(c in _PUNCTUATION for c in pwd),
        "space": " " in pwd,
    }


CHECK = "get-random-password-satisfies-every-constraint"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRandomPassword output honours every length, include and exclude knob, two calls differ,
    and a constraint set that empties the alphabet is refused rather than silently satisfied.
    """
    sm = ctx.client("secretsmanager")

    # 1. RequireEachIncludedType: every class that is NOT excluded must appear.
    strong = sm.get_random_password(PasswordLength=64, RequireEachIncludedType=True)[
        "RandomPassword"
    ]
    assert len(strong) == 64, f"PasswordLength=64 must yield exactly 64 chars, got {len(strong)}"
    present = _classes(strong)
    for cls in ("lower", "upper", "digit", "punct"):
        assert present[cls], (
            f"RequireEachIncludedType=True must guarantee at least one {cls} character; "
            f"classes present were {present}"
        )

    # 2. Each class exclusion individually removes exactly that class and nothing else.
    no_digits = sm.get_random_password(
        PasswordLength=48, ExcludeNumbers=True, RequireEachIncludedType=True
    )["RandomPassword"]
    assert len(no_digits) == 48, f"PasswordLength=48 must yield exactly 48 chars, got {len(no_digits)}"
    assert not any(c in string.digits for c in no_digits), (
        "ExcludeNumbers=True must keep every digit out of the generated password"
    )
    assert _classes(no_digits)["lower"] and _classes(no_digits)["upper"], (
        "ExcludeNumbers must not suppress the other required classes; "
        f"classes were {_classes(no_digits)}"
    )

    no_upper = sm.get_random_password(
        PasswordLength=48, ExcludeUppercase=True, RequireEachIncludedType=True
    )["RandomPassword"]
    assert not any(c in string.ascii_uppercase for c in no_upper), (
        "ExcludeUppercase=True must keep every A-Z out of the generated password"
    )

    no_lower = sm.get_random_password(
        PasswordLength=48, ExcludeLowercase=True, RequireEachIncludedType=True
    )["RandomPassword"]
    assert not any(c in string.ascii_lowercase for c in no_lower), (
        "ExcludeLowercase=True must keep every a-z out of the generated password"
    )

    # 3. IncludeSpace puts the space character INTO the alphabet; the default keeps it out.
    # RequireEachIncludedType guarantees only upper, lower, digit and punctuation, so a space
    # appears by chance. A 256-character draw from 95 characters misses it with probability
    # (94/95)**256 ~= 0.066, so _SPACE_DRAWS=12 independent misses is ~1e-13.
    space_seen = 0
    for _ in range(_SPACE_DRAWS):
        spaced = sm.get_random_password(
            PasswordLength=256, IncludeSpace=True, RequireEachIncludedType=True
        )["RandomPassword"]
        assert len(spaced) == 256, f"PasswordLength=256 must yield 256 chars, got {len(spaced)}"
        spaced_classes = _classes(spaced)
        for cls in ("lower", "upper", "digit", "punct"):
            assert spaced_classes[cls], (
                f"RequireEachIncludedType=True still guarantees a {cls} character when IncludeSpace "
                f"is on; classes present were {spaced_classes}"
            )
        space_seen += " " in spaced
    assert space_seen, (
        f"IncludeSpace=True must put the space character in the alphabet, but none of "
        f"{_SPACE_DRAWS} independent 256-character draws contained one"
    )

    # ...and the default must NOT, over the same number of draws, or a caller's shell quoting
    # silently breaks. One draw could miss spaces emitted unconditionally, so the negative side
    # is measured over the same run length.
    for _ in range(_SPACE_DRAWS):
        plain = sm.get_random_password(PasswordLength=256, RequireEachIncludedType=True)[
            "RandomPassword"
        ]
        assert " " not in plain, (
            "IncludeSpace defaults to false, so the default password must contain no space; got "
            f"{plain!r}"
        )

    # 4. ExcludeCharacters is honoured together with a class exclusion.
    banned = "l1IO0"
    picky = sm.get_random_password(
        PasswordLength=40, ExcludeCharacters=banned, ExcludePunctuation=True
    )["RandomPassword"]
    assert len(picky) == 40, f"PasswordLength=40 must yield exactly 40 chars, got {len(picky)}"
    offending = sorted({c for c in picky if c in banned})
    assert not offending, f"ExcludeCharacters={banned!r} was violated by {offending}"
    assert not any(c in _PUNCTUATION for c in picky), (
        "ExcludePunctuation=True must be honoured alongside ExcludeCharacters"
    )

    # 5. The output must be random, not a constant. Two 64-char draws colliding by
    #    chance is astronomically unlikely, so an equal pair means a fixed value.
    a = sm.get_random_password(PasswordLength=64)["RandomPassword"]
    b = sm.get_random_password(PasswordLength=64)["RandomPassword"]
    assert a != b, (
        "two consecutive GetRandomPassword calls returned an identical string, so the "
        "implementation is returning a constant rather than generating a password"
    )

    # 6. A contradictory constraint set -- every class excluded while each is also
    #    required -- leaves no legal alphabet and must be refused, not silently
    #    satisfied with an empty or partial password.
    err = _error(
        lambda: sm.get_random_password(
            PasswordLength=32,
            ExcludeNumbers=True,
            ExcludePunctuation=True,
            ExcludeUppercase=True,
            ExcludeLowercase=True,
            RequireEachIncludedType=True,
        )
    )
    # InvalidRequestException, not InvalidParameterException: an alphabet emptied by an
    # otherwise-legal combination of parameters is a bad request as a whole.
    assert err.get("Code") == "InvalidRequestException", (
        "excluding every character class while requiring each included type leaves no "
        f"legal alphabet and must be rejected with InvalidRequestException, got {err}"
    )
    assert err.get("Message") == "All characters have been excluded from selection.", (
        f"unexpected message: {err.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
