"""pod-identity-clustername-constraint-boundaries-rejected."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags

CHECK = "pod-identity-clustername-constraint-boundaries-rejected"
GROUP = 'overly-permissive'
SERVICES = ['eks-auth']

_BAD_KID = "The token included in the request has invalid header - kid."
_PATTERN_TEXT = ("failed to satisfy constraint: Member must satisfy regular expression "
                 "pattern: [0-9A-Za-z][A-Za-z0-9\\-_]*")
_LENGTH_TEXT = ("failed to satisfy constraint: Member must have length less than or equal "
                "to 100")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRoleForPodIdentity admits a 100-character clusterName and names with a later '-' or '_' (they
    reach token validation: InvalidTokenException), but refuses 101 characters and a leading '-'/'_', dot,
    space or non-ASCII letter with InvalidParameterException naming the value.
    """
    ea = ctx.client("eks-auth")

    def _b64(obj) -> str:
        """base64url without padding -- the only alphabet the token @pattern admits."""
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    def _error_identity(fn) -> tuple[str, str]:
        """Call fn, require it to raise, return the exact (Code, Message).

        Raises on unexpected SUCCESS rather than returning a falsy sentinel: an emulator
        that MINTS credentials here is the strongest possible finding and must not read as
        an error-code mismatch.
        """
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001 -- botocore ClientError, by shape not class
            response = getattr(exc, "response", None)
            assert response is not None, (
                f"expected a modelled AWS error, got {type(exc).__name__}: {exc!r}"
            )
            err = response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(
            "AssumeRoleForPodIdentity SUCCEEDED with an unresolvable token; "
            f"response members were {sorted(result)!r}"
        )

    # One token, held constant across every name, whose kid cannot resolve against any
    # cluster's JWKS. It is the deepest state reachable without a cluster, so reaching it is
    # exactly "the name cleared the constraint layer".
    now = int(time.time())
    token = (
        f"{_b64({'alg': 'RS256', 'typ': 'JWT', 'kid': 'sim2realbehaveksauthKid00000000000000000000'})}"
        f".{_b64({'aud': ['pods.eks.amazonaws.com'], 'iat': now, 'exp': now + 3600})}"
        ".c2lnbmF0dXJl"
    )

    def _call(name: str) -> tuple[str, str]:
        return _error_identity(
            lambda: ea.assume_role_for_pod_identity(clusterName=name, token=token)
        )

    # (a) ACCEPTED -- the constraint layer passes these through to token validation.
    #     'a' and '0' are the @length minimum; 'a'*100 is the maximum.
    accepted = {
        "single lower-case letter (length minimum)": "a",
        "single digit (the pattern's first class includes 0-9)": "0",
        "exactly 100 characters (the length maximum)": "a" * 100,
        "trailing hyphen": "sim2realbehav-",
        "inner hyphen and underscore, mixed case and digits": "sim2real_behav-CN9",
    }
    accepted_identities = {}
    for label, name in accepted.items():
        accepted_identities[label] = _call(name)
    for label, identity in accepted_identities.items():
        assert identity == ("InvalidTokenException", _BAD_KID), (
            f"clusterName {accepted[label]!r} ({label}) returned {identity!r}; real AWS "
            f"admits this name and fails one layer deeper, at "
            f"('InvalidTokenException', {_BAD_KID!r})"
        )

    # (b) REFUSED for LENGTH -- 101 characters, one past the inclusive maximum that (a)
    #     just proved is accepted at 100.
    over_length = "a" * 101
    length_identity = _call(over_length)
    assert length_identity == (
        "InvalidParameterException",
        f"1 validation error detected: Value '{over_length}' at 'clusterName' {_LENGTH_TEXT}",
    ), (
        f"a 101-character clusterName returned {length_identity!r}; real AWS refuses it at "
        "the constraint layer with the aggregated InvalidParameterException, while 100 "
        "characters is accepted -- the bound is inclusive at both ends"
    )

    # (c) REFUSED for PATTERN. '_sim2realbehav' and 'sim2real_behav-CN9' differ only in WHERE
    #     the underscore sits, which is what makes the asymmetry observable.
    pattern_refused = {
        "leading underscore, legal in any later position": "_sim2realbehav",
        "leading hyphen, legal in any later position": "-sim2realbehav",
        "dot": "sim2real.behav",
        "space": "sim2real behav",
        "non-ASCII letter": "sim2realbehavé",
    }
    pattern_identities = {}
    for label, name in pattern_refused.items():
        pattern_identities[label] = _call(name)
    for label, identity in pattern_identities.items():
        name = pattern_refused[label]
        assert identity == (
            "InvalidParameterException",
            f"1 validation error detected: Value '{name}' at 'clusterName' {_PATTERN_TEXT}",
        ), (
            f"clusterName {name!r} ({label}) returned {identity!r}; real AWS refuses it at "
            "the constraint layer, echoing the offending value and naming 'clusterName'"
        )

    # (d) The partition is real: nothing that was accepted shares an identity with anything
    #     that was refused. An emulator that refuses the whole set, or admits the whole set,
    #     fails here even if it reproduces each individual message.
    refused_identities = set(pattern_identities.values()) | {length_identity}
    assert not (set(accepted_identities.values()) & refused_identities), (
        "the accepted and refused names must land in disjoint outcomes, but they overlap: "
        f"accepted {sorted(set(accepted_identities.values()))!r} vs refused "
        f"{sorted(refused_identities)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
