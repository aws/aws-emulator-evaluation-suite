"""op-contract-getLifecyclePolicy."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getLifecyclePolicy"
GROUP = "error-semantics"
SERVICES = ["ecr"]

_POLICY = {
    "rules": [
        {
            "rulePriority": 1,
            "description": "expire untagged after 1 image",
            "selection": {
                "tagStatus": "untagged",
                "countType": "imageCountMoreThan",
                "countNumber": 1,
            },
            "action": {"type": "expire"},
        }
    ]
}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLifecyclePolicy returns exactly the lifecyclePolicyText set via PutLifecyclePolicy;
    calling it on a repository with no policy configured raises LifecyclePolicyNotFoundException."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ctx)
    name = repo["repositoryName"]
    policy_text = json.dumps(_POLICY)
    ecr.put_lifecycle_policy(repositoryName=name, lifecyclePolicyText=policy_text)

    resp = ecr.get_lifecycle_policy(repositoryName=name)
    assert resp["repositoryName"] == name, (
        f"expected repositoryName {name!r}, got {resp['repositoryName']!r}"
    )
    assert json.loads(resp["lifecyclePolicyText"]) == _POLICY, (
        f"expected lifecyclePolicyText to round-trip {_POLICY!r}, "
        f"got {json.loads(resp['lifecyclePolicyText'])!r}"
    )

    fresh_repo = _create_repo(ctx)
    code, message = _error(lambda: ecr.get_lifecycle_policy(repositoryName=fresh_repo["repositoryName"]))
    assert code == "LifecyclePolicyNotFoundException", (
        f"expected LifecyclePolicyNotFoundException for a repo with no policy configured, "
        f"got {code!r}"
    )
    expected = f"Lifecycle policy does not exist for the repository with name '{fresh_repo['repositoryName']}' in the registry with id '{ctx.account}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ctx, **kwargs: Any) -> dict:
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
