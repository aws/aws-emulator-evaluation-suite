"""catalog-resource-policy-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "catalog-resource-policy-lifecycle"
GROUP = 'resource-policy'
SERVICES = ['glue']


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _delete_policy_ignore_missing(glue) -> None:
    """Teardown: the check deletes the policy itself, so it is usually gone already."""
    try:
        glue.delete_resource_policy()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:glue-catalog-policy")
def run(ctx) -> None:
    """Catalog resource policy put -> get (hash) -> delete, stale-hash writes are rejected without
    effect, and a double-delete still 404s."""
    glue = ctx.client("glue")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    catalog_arn = f"arn:aws:glue:{region}:{account}:catalog"

    # Adopt: clear any policy a prior run left behind, so a re-run against a dirty
    # catalog still exercises the no-policy 404 rather than failing on the precondition.
    try:
        glue.delete_resource_policy()
    except ClientError:
        pass
    absent = _error(lambda: glue.get_resource_policy())
    assert absent == ("EntityNotFoundException", "Policy not found"), (
        f"a catalog with no resource policy must 404 on GetResourcePolicy, got {absent}"
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": ["glue:GetDatabase"],
                "Resource": [catalog_arn],
            }
        ],
    }
    glue.put_resource_policy(PolicyInJson=json.dumps(policy))
    ctx.on_cleanup(lambda: _delete_policy_ignore_missing(glue))
    try:
        got = glue.get_resource_policy()
        assert "glue:GetDatabase" in got["PolicyInJson"], (
            f"PutResourcePolicy did not persist the policy body: {got}"
        )
        policy_hash = got["PolicyHash"]
        assert policy_hash, "GetResourcePolicy must return a PolicyHash for optimistic locking"

        # GetResourcePolicies enumerates per-resource (RAM) grants; the catalog-level policy set
        # by PutResourcePolicy must not leak into that separate listing.
        policies = glue.get_resource_policies()["GetResourcePoliciesResponseList"]
        assert isinstance(policies, list), f"GetResourcePolicies must return a list: {policies!r}"
        assert not any(catalog_arn in p.get("PolicyInJson", "") for p in policies), (
            f"the catalog-level policy must not be enumerated by GetResourcePolicies: {policies!r}"
        )

        # Optimistic concurrency: a stale hash must be refused.
        stale = _error(
            lambda: glue.put_resource_policy(
                PolicyInJson=json.dumps(policy),
                PolicyHashCondition="00000000000000000000000000000000",
            )
        )
        assert stale == ("ConditionCheckFailureException", "Policy not exists or policy hash mismatch"), (
            f"a stale PolicyHashCondition must be rejected, got {stale}"
        )

        # The rejected stale write must not have taken effect.
        unchanged = glue.get_resource_policy()
        assert unchanged["PolicyHash"] == policy_hash, (
            f"a rejected stale-hash PutResourcePolicy changed the stored hash: "
            f"{unchanged['PolicyHash']!r} != {policy_hash!r}"
        )

        # The correct hash is accepted, and an independent read confirms it landed.
        glue.put_resource_policy(PolicyInJson=json.dumps(policy), PolicyHashCondition=policy_hash)
        confirmed = glue.get_resource_policy()
        assert "glue:GetDatabase" in confirmed["PolicyInJson"], (
            f"the correct-hash PutResourcePolicy did not persist: {confirmed}"
        )
    finally:
        try:
            glue.delete_resource_policy()
        except Exception:
            pass

    gone = _error(lambda: glue.get_resource_policy())
    assert gone == ("EntityNotFoundException", "Policy not found"), (
        f"DeleteResourcePolicy must leave the catalog with no policy, got {gone}"
    )
    redelete = _error(lambda: glue.delete_resource_policy())
    assert redelete == ("EntityNotFoundException", "Policy not found"), (
        f"DeleteResourcePolicy on an already-deleted catalog policy must still 404, not succeed, got {redelete}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
