"""assume-role-concurrent-invalid-requests-consistent-error."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-concurrent-invalid-requests-consistent-error"
GROUP = "concurrency"
SERVICES = ["eks-auth"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Ten concurrent AssumeRoleForPodIdentity calls with the same invalid token against an unknown cluster
    all fail with InvalidTokenException.
    """
    eks_auth = ctx.client("eks-auth")
    bogus_cluster = ctx.unique_name("sim2real-nonexistent-")
    plausible_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

    def _call(_: int):
        return _error_code(
            lambda: eks_auth.assume_role_for_pod_identity(clusterName=bogus_cluster, token=plausible_token)
        )

    with ThreadPoolExecutor(max_workers=10) as pool:
        codes = list(pool.map(_call, range(10)))

    assert codes == ["InvalidTokenException"] * 10, f"GOT={codes!r}"


def _error_code(fn):
    """Call fn(); return its botocore Error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
