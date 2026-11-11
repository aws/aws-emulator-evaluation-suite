"""pod-identity-header-rejection-layers-are-ordered."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags

CHECK = "pod-identity-header-rejection-layers-are-ordered"
GROUP = 'error-semantics'
SERVICES = ['eks-auth']

_PARSE = "Failed to parse the token included in the request."
_BAD_ALG = "The token included in the request has invalid header - alg."
_MISSING_KID = "The token included in the request has missing header - kid."
_BAD_KID = "The token included in the request has invalid header - kid."
_CN_PATTERN = (
    "1 validation error detected: Value '-sim2realbehav' at 'clusterName' failed to satisfy "
    "constraint: Member must satisfy regular expression pattern: [0-9A-Za-z][A-Za-z0-9\\-_]*"
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRoleForPodIdentity reports only the shallowest of its ordered rejection layers: clusterName/token
    constraints, token parse, alg not RS256, missing kid, unresolvable kid, each with its exact code and
    message for a request that is wrong at that layer and every deeper one.
    """
    ea = ctx.client("eks-auth")

    def _b64(obj) -> str:
        """base64url without padding -- the only alphabet the token @pattern admits."""
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    def _error_identity(fn) -> tuple[str, str]:
        """Call fn, require it to raise, return the exact (Code, Message).

        Raises on unexpected SUCCESS rather than returning a falsy sentinel: an emulator
        that MINTS credentials for one of these tokens is the strongest possible finding and
        must not read as an error-code mismatch.
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

    now = int(time.time())
    claims = _b64({"aud": ["pods.eks.amazonaws.com"], "iat": now, "exp": now + 3600,
                   "sub": "system:serviceaccount:default:sim2real-behav-sa"})
    kid = "sim2realbehaveksauthKid00000000000000000000"
    cluster = "sim2realbehavabsentcluster"          # pattern-valid, absent from this account
    bad_cluster = "-sim2realbehav"                  # violates the leading-character pattern

    def _call(cluster_name: str, header: dict) -> tuple[str, str]:
        return _error_identity(
            lambda: ea.assume_role_for_pod_identity(
                clusterName=cluster_name,
                token=f"{_b64(header)}.{claims}.c2lnbmF0dXJl")
        )

    # Layer 0 -- the Smithy constraint layer outranks EVERY token layer. This request is also
    # wrong at layer 2 (alg) and layer 3 (blank kid), and neither is reported.
    layer0 = _call(bad_cluster, {"alg": "HS256", "kid": ""})
    assert layer0 == ("InvalidParameterException", _CN_PATTERN), (
        f"a pattern-invalid clusterName alongside a bad alg and a blank kid returned "
        f"{layer0!r}; real AWS reports only the constraint violation, as "
        f"('InvalidParameterException', {_CN_PATTERN!r})"
    )

    # Layer 1 -- structural parse outranks the alg and kid layers. `alg` is absent, and the
    # kid is blank, which would be layer 3 if the header parsed at all.
    layer1 = _call(cluster, {"kid": ""})
    assert layer1 == ("InvalidTokenException", _PARSE), (
        f"a header with no `alg` and a blank `kid` returned {layer1!r}; a header missing "
        f"`alg` does not parse, so real AWS reports ('InvalidTokenException', {_PARSE!r}) "
        "and never reaches the kid layer"
    )

    # Layer 2 -- the alg VALUE outranks the kid layers. Same blank kid as layer 1.
    layer2 = _call(cluster, {"alg": "HS256", "kid": ""})
    assert layer2 == ("InvalidTokenException", _BAD_ALG), (
        f"alg='HS256' with a blank `kid` returned {layer2!r}; real AWS rejects the alg "
        f"first, as ('InvalidTokenException', {_BAD_ALG!r}) -- only RS256 is accepted"
    )

    # Layer 3 -- kid PRESENCE outranks kid resolution. The blank kid is treated as absent.
    layer3 = _call(cluster, {"alg": "RS256", "kid": ""})
    assert layer3 == ("InvalidTokenException", _MISSING_KID), (
        f"alg='RS256' with kid='' returned {layer3!r}; real AWS treats a blank kid as "
        f"ABSENT, as ('InvalidTokenException', {_MISSING_KID!r}), not as an unresolvable one"
    )

    # Layer 4 -- the deepest state reachable without a real cluster, and therefore the
    # control: landing here proves layers 0-3 were all cleared by this request.
    layer4 = _call(cluster, {"alg": "RS256", "typ": "JWT", "kid": kid})
    assert layer4 == ("InvalidTokenException", _BAD_KID), (
        f"a well-formed RS256 header with a non-blank, unresolvable kid returned {layer4!r}; "
        f"real AWS reaches kid resolution and reports ('InvalidTokenException', {_BAD_KID!r})"
    )

    # The layers must be DISTINGUISHABLE, or the ordering above is unobservable to a caller
    # and an emulator could collapse them all onto one message and still pass.
    token_layers = {"parse": layer1, "alg": layer2, "kid-presence": layer3,
                    "kid-resolution": layer4}
    assert len(set(token_layers.values())) == 4, (
        "the four token-header layers must be distinguishable, but they produced "
        f"{len(set(token_layers.values()))} distinct identities: {token_layers!r}"
    )
    for name, identity in token_layers.items():
        assert identity[0] == "InvalidTokenException", (
            f"token layer {name!r} was reported as {identity[0]!r} ({identity[1]!r}); every "
            "token-header rejection on real AWS is InvalidTokenException"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
