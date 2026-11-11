"""lifecycle-policy-invalid-json-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]

CHECK = "lifecycle-policy-invalid-json-rejected"
GROUP = 'error-semantics'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutLifecyclePolicy with unparseable JSON of at least 100 characters is refused
    InvalidParameterException with the exact message, and the valid policy put before still reads
    back unchanged."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name)

    valid_policy = json.dumps(
        {
            "rules": [
                {
                    "rulePriority": 1,
                    "description": "Expire untagged images older than 14 days",
                    "selection": {
                        "tagStatus": "untagged",
                        "countType": "sinceImagePushed",
                        "countUnit": "days",
                        "countNumber": 14,
                    },
                    "action": {"type": "expire"},
                }
            ]
        }
    )
    ecr.put_lifecycle_policy(repositoryName=name, lifecyclePolicyText=valid_policy)

    bad_policy = "{not valid json " + ("x" * 120)
    assert len(bad_policy) >= 100

    code, message = _error(
        lambda: ecr.put_lifecycle_policy(
            repositoryName=name, lifecyclePolicyText=bad_policy
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == (
        "Invalid parameter at 'LifecyclePolicyText' failed to satisfy constraint: 'Lifecycle policy parsing failure: Could not map policyString into LifecyclePolicy.'"
    ), message

    unchanged = ecr.get_lifecycle_policy(repositoryName=name)
    assert json.loads(unchanged["lifecyclePolicyText"]) == json.loads(valid_policy), (
        f"rejected PutLifecyclePolicy must not affect the existing policy, "
        f"got {unchanged['lifecyclePolicyText']!r} expected {valid_policy!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
