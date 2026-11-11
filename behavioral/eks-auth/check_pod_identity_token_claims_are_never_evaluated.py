"""pod-identity-token-claims-are-never-evaluated."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags

CHECK = "pod-identity-token-claims-are-never-evaluated"
GROUP = 'error-semantics'
SERVICES = ['eks-auth']

_INVALID_KID = "The token included in the request has invalid header - kid."
_MISSING_KID = "The token included in the request has missing header - kid."


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRoleForPodIdentity returns one identical InvalidTokenException "invalid header - kid" for five
    different claim bodies (valid, expired, wrong audience, empty, non-object), never the declared
    ExpiredTokenException, while dropping kid from the header moves it to "missing header - kid".
    """
    ea = ctx.client("eks-auth")

    def _b64(obj) -> str:
        """base64url without padding -- the only alphabet the token @pattern admits."""
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    def _token(header: dict, payload_segment: str) -> str:
        return f"{_b64(header)}.{payload_segment}.c2lnbmF0dXJl"

    def _error_identity(fn) -> tuple[str, str]:
        """Call fn, require it to raise, return the exact (Code, Message).

        Raises on unexpected SUCCESS rather than returning a falsy sentinel: an emulator
        that MINTS credentials for one of these tokens is the strongest possible finding
        and must not read as an error-code mismatch.
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
            "AssumeRoleForPodIdentity SUCCEEDED on a token real AWS rejects; "
            f"response members were {sorted(result)!r}"
        )

    # A well-formed RS256 header whose kid cannot resolve against any cluster's JWKS.
    # Every variant below shares it, so the ONLY thing that differs is the claims.
    header = {"alg": "RS256", "typ": "JWT",
              "kid": "sim2realbehaveksauthKid00000000000000000000"}
    now = int(time.time())
    issuer = f"https://oidc.eks.{ctx.region}.amazonaws.com/id/SIM2REALBEHAVNOTACLUSTER"
    subject = "system:serviceaccount:default:sim2real-behav-sa"

    claims_variants = {
        "inside its validity window": _b64({
            "aud": ["pods.eks.amazonaws.com"], "iss": issuer, "sub": subject,
            "iat": now, "exp": now + 3600}),
        "expired an hour ago": _b64({
            "aud": ["pods.eks.amazonaws.com"], "iss": issuer, "sub": subject,
            "iat": now - 7200, "exp": now - 3600}),
        "wrong audience": _b64({
            "aud": ["sts.amazonaws.com"], "iss": issuer, "sub": subject,
            "iat": now, "exp": now + 3600}),
        "no claims at all": _b64({}),
        # Not a JSON object at all: if any claim were read, this could not survive as far
        # as kid resolution.
        "a payload that is not even JSON":
            base64.urlsafe_b64encode(b"sim2real-not-json-at-all").decode().rstrip("="),
    }

    # The cluster name is pattern-valid and absent from this account, held CONSTANT so it
    # cannot be the thing that differs either.
    cluster = "sim2realbehavabsentcluster"

    identities = {}
    for label, payload in claims_variants.items():
        identities[label] = _error_identity(
            lambda p=payload: ea.assume_role_for_pod_identity(
                clusterName=cluster, token=_token(header, p))
        )

    # (a) Every claims variant is rejected with the SAME exact code.
    for label, (code, message) in identities.items():
        assert code == "InvalidTokenException", (
            f"claims variant {label!r} was rejected as {code!r} ({message!r}); real AWS "
            "returns InvalidTokenException for every one of these"
        )

    # (b) ...and the SAME exact message, so the five are indistinguishable to a caller.
    distinct = set(identities.values())
    assert len(distinct) == 1, (
        "the claims ARE being evaluated: five semantically different claim bodies produced "
        f"{len(distinct)} distinct (code, message) identities, {sorted(distinct)!r}; real "
        f"AWS collapses all five onto ('InvalidTokenException', {_INVALID_KID!r})"
    )
    assert distinct == {("InvalidTokenException", _INVALID_KID)}, (
        f"the single collapsed identity was {sorted(distinct)!r}, expected "
        f"('InvalidTokenException', {_INVALID_KID!r}) -- validation must stop at kid "
        "resolution, before any claim is read"
    )

    # (c) The declared-but-unreachable errors are ABSENT. Stated separately from (b)
    #     because it is the consequence an emulator gets wrong by implementing the model.
    unreachable = {"ExpiredTokenException", "AccessDeniedException",
                   "ResourceNotFoundException", "InvalidRequestException"}
    for label, (code, message) in identities.items():
        assert code not in unreachable, (
            f"claims variant {label!r} reached {code!r} ({message!r}); that error is "
            "declared on AssumeRoleForPodIdentity but unreachable on real AWS, which "
            "never reads the claims"
        )

    # (d) The discriminating control: a HEADER change in the same position DOES move the
    #     identity. This is what makes (b) a measurement rather than a tautology.
    header_without_kid = {"alg": "RS256", "typ": "JWT"}
    control = _error_identity(
        lambda: ea.assume_role_for_pod_identity(
            clusterName=cluster,
            token=_token(header_without_kid, claims_variants["inside its validity window"]))
    )
    assert control == ("InvalidTokenException", _MISSING_KID), (
        f"the discriminating control returned {control!r}, expected "
        f"('InvalidTokenException', {_MISSING_KID!r}); without a control that MOVES the "
        "identity, the collapse asserted above would be unfalsifiable"
    )
    assert control not in distinct, (
        f"dropping kid produced the same identity {control!r} as leaving it unresolvable -- "
        "the header layer must discriminate even though the claims layer does not"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
