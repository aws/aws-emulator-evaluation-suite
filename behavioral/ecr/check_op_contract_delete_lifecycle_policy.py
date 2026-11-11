"""op-contract-deleteLifecyclePolicy."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteLifecyclePolicy"
GROUP = "error-semantics"
SERVICES = ["ecr"]

_POLICY = {
    "rules": [
        {
            "rulePriority": 1,
            "description": "expire beyond newest 1",
            "selection": {
                "tagStatus": "any",
                "countType": "imageCountMoreThan",
                "countNumber": 1,
            },
            "action": {"type": "expire"},
        }
    ]
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteLifecyclePolicy returns the deleted policy text, after which Get and a repeat delete
    are refused LifecyclePolicyNotFoundException with the exact message, and the repository
    accepts a new policy."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ctx)
    name = repo["repositoryName"]
    policy_text = json.dumps(_POLICY)
    ecr.put_lifecycle_policy(repositoryName=name, lifecyclePolicyText=policy_text)

    resp = ecr.delete_lifecycle_policy(repositoryName=name)
    assert resp["repositoryName"] == name, f"expected repositoryName {name!r}, got {resp.get('repositoryName')!r}"
    assert json.loads(resp["lifecyclePolicyText"]) == _POLICY, (
        f"expected deleted lifecyclePolicyText to echo {_POLICY!r}, got {resp.get('lifecyclePolicyText')!r}"
    )

    not_found = (
        f"Lifecycle policy does not exist for the repository with name '{name}' in the registry "
        f"with id '{ctx.account}'"
    )
    code, message = _error(lambda: ecr.get_lifecycle_policy(repositoryName=name))
    assert code == "LifecyclePolicyNotFoundException", f"expected LifecyclePolicyNotFoundException, got {code!r}"
    assert message == not_found, f"expected message {not_found!r}, got {message!r}"

    code_again, message = _error(lambda: ecr.delete_lifecycle_policy(repositoryName=name))
    assert code_again == "LifecyclePolicyNotFoundException", (
        f"expected repeat delete to raise LifecyclePolicyNotFoundException, got {code_again!r}"
    )
    assert message == not_found, f"expected message {not_found!r}, got {message!r}"

    ecr.put_lifecycle_policy(repositoryName=name, lifecyclePolicyText=policy_text)
    reset = ecr.get_lifecycle_policy(repositoryName=name)
    assert json.loads(reset["lifecyclePolicyText"]) == _POLICY, (
        f"expected the repository to accept a fresh policy after the delete, got {reset.get('lifecyclePolicyText')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ctx, **kwargs: Any) -> dict:
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
