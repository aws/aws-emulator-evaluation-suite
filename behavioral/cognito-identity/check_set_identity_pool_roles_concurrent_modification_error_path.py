"""set-identity-pool-roles-concurrent-modification-error-path."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-identity-pool-roles-concurrent-modification-error-path"
GROUP = "concurrency"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Overlapping SetIdentityPoolRoles calls on the same pool never corrupt the role
    binding: every racer either succeeds or fails with ConcurrentModificationException,
    and the final authenticated role ARN matches exactly one of the attempted writes."""
    ci = ctx.client("cognito-identity")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    pool_id = _create_pool(ctx, ci)

    racer_count = 10
    candidate_arns = [
        f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-behav-role-')}-{i}"
        for i in range(racer_count)
    ]

    def _attempt(role_arn: str):
        try:
            ci.set_identity_pool_roles(
                IdentityPoolId=pool_id, Roles={"authenticated": role_arn}
            )
            return ("ok", role_arn)
        except ClientError as exc:
            err = exc.response["Error"]
            return ("error", (err["Code"], err.get("Message")))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_attempt, arn) for arn in candidate_arns]
        results = [f.result() for f in as_completed(futures)]

    successes = [r for kind, r in results if kind == "ok"]
    errors = [r for kind, r in results if kind == "error"]

    expected = (
        "ConcurrentModificationException",
        "Only one request to update resource type Identity Pool can be processed at a time",
    )
    for err in errors:
        assert err == expected, (err, expected)
    assert len(successes) >= 1, results

    final = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert final["Roles"]["authenticated"] in candidate_arns, final["Roles"]


def _create_pool(ctx, ci, *, unauth: bool = True) -> str:
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=unauth,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
