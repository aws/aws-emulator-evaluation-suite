"""pod-identity-absent-cluster-rejected-on-token-not-existence."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags

CHECK = "pod-identity-absent-cluster-rejected-on-token-not-existence"
GROUP = 'error-semantics'
SERVICES = ['eks', 'eks-auth']

_BAD_KID = "The token included in the request has invalid header - kid."
_CN_PATTERN = (
    "1 validation error detected: Value '-sim2realbehav' at 'clusterName' failed to satisfy "
    "constraint: Member must satisfy regular expression pattern: [0-9A-Za-z][A-Za-z0-9\\-_]*"
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For an absent cluster name, EKS answers ResourceNotFoundException while eks-auth
    AssumeRoleForPodIdentity answers InvalidTokenException: it validates clusterName's pattern
    but never resolves the name, so it reveals nothing about cluster existence.

    Reference: https://docs.aws.amazon.com/eks/latest/APIReference/API_auth_AssumeRoleForPodIdentity.html
    """
    eks = ctx.client("eks")
    ea = ctx.client("eks-auth")

    def _b64(obj) -> str:
        """base64url without padding -- the only alphabet the token @pattern admits."""
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    def _error_identity(fn) -> tuple[str, str]:
        """Call fn, require it to raise, return the exact (Code, Message).

        Raises on unexpected success so minted credentials do not read as a code mismatch.
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
            f"the call SUCCEEDED against a cluster that does not exist; response members "
            f"were {sorted(result)!r}"
        )

    absent = "sim2realbehavabsentcluster"   # pattern-valid, and never created by this check
    bad_name = "-sim2realbehav"             # violates the leading-character pattern

    # (a) The name is genuinely absent. Paginated, because other clusters can fill page one.
    existing = []
    for page in eks.get_paginator("list_clusters").paginate():
        existing.extend(page["clusters"])
    assert absent not in existing, (
        f"the premise of this check is broken: {absent!r} EXISTS in this account, whose "
        f"clusters are {sorted(existing)!r}"
    )

    # (b) EKS proper reports the absence, on the cluster itself and on its pod-identity
    #     sub-resource -- the closest sibling of the operation under test.
    not_found = f"No cluster found for name: {absent}."
    describe = _error_identity(lambda: eks.describe_cluster(name=absent))
    assert describe == ("ResourceNotFoundException", not_found), (
        f"EKS DescribeCluster on {absent!r} returned {describe!r}, expected "
        f"('ResourceNotFoundException', {not_found!r}); without this the divergence below "
        "could not be attributed to eks-auth"
    )
    list_assoc = _error_identity(
        lambda: eks.list_pod_identity_associations(clusterName=absent)
    )
    assert list_assoc == ("ResourceNotFoundException", not_found), (
        f"EKS ListPodIdentityAssociations on {absent!r} returned {list_assoc!r}, expected "
        f"('ResourceNotFoundException', {not_found!r})"
    )

    # (c) eks-auth, same name, same account, same moment: the TOKEN error, not a 404.
    now = int(time.time())
    token = (
        f"{_b64({'alg': 'RS256', 'typ': 'JWT', 'kid': 'sim2realbehaveksauthKid00000000000000000000'})}"
        f".{_b64({'aud': ['pods.eks.amazonaws.com'], 'iat': now, 'exp': now + 3600})}"
        ".c2lnbmF0dXJl"
    )
    pod_identity = _error_identity(
        lambda: ea.assume_role_for_pod_identity(clusterName=absent, token=token)
    )
    assert pod_identity == ("InvalidTokenException", _BAD_KID), (
        f"eks-auth AssumeRoleForPodIdentity on the absent cluster {absent!r} returned "
        f"{pod_identity!r}; real AWS never resolves clusterName and reports "
        f"('InvalidTokenException', {_BAD_KID!r})"
    )

    # (d) The divergence, stated as such: the two services disagree on the same identifier.
    assert pod_identity[0] != describe[0], (
        f"eks-auth and EKS proper both reported {pod_identity[0]!r} for the absent cluster "
        f"{absent!r}; on real AWS only EKS resolves the name, so the codes must differ"
    )

    # (e) eks-auth DOES read clusterName -- it just never resolves it. This is the control
    #     that separates "not resolved" from "not received".
    refused = _error_identity(
        lambda: ea.assume_role_for_pod_identity(clusterName=bad_name, token=token)
    )
    assert refused == ("InvalidParameterException", _CN_PATTERN), (
        f"eks-auth returned {refused!r} for the pattern-invalid clusterName {bad_name!r}; "
        f"real AWS refuses it at the constraint layer as "
        f"('InvalidParameterException', {_CN_PATTERN!r}), which proves clusterName is read"
    )

    # (f) The effect is absent from EKS's side too: no association appeared for a cluster
    #     that still does not exist, so nothing about (c) created state.
    still_absent = _error_identity(
        lambda: eks.list_pod_identity_associations(clusterName=absent)
    )
    assert still_absent == ("ResourceNotFoundException", not_found), (
        f"after the AssumeRoleForPodIdentity attempt, EKS reported {still_absent!r} for "
        f"{absent!r}; the cluster must remain absent and unmodified"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
