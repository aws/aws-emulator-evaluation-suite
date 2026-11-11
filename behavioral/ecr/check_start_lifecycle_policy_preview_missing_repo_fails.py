"""start-lifecycle-policy-preview-missing-repo-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-lifecycle-policy-preview-missing-repo-fails"
GROUP = 'overly-permissive'
SERVICES = ['ecr']



def _client_error(fn):
    """Call fn(); return its botocore (Error code, Error message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"expected RepositoryNotFoundException, but the call SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartLifecyclePolicyPreview on a nonexistent repository fails with RepositoryNotFoundException
    and creates nothing; the same call succeeds once the repository exists."""
    ecr = ctx.client("ecr")
    missing = ctx.unique_name("sim2real-behav-ecr-absent-")
    policy_text = json.dumps(
        {
            "rules": [
                {
                    "rulePriority": 1,
                    "description": "expire untagged images beyond the newest one",
                    "selection": {
                        "tagStatus": "untagged",
                        "countType": "imageCountMoreThan",
                        "countNumber": 1,
                    },
                    "action": {"type": "expire"},
                }
            ]
        }
    )
    code, message = _client_error(
        lambda: ecr.start_lifecycle_policy_preview(
            repositoryName=missing, lifecyclePolicyText=policy_text
        )
    )
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
    assert message == (
        f"The repository with name '{missing}' does not exist in the registry with id "
        f"'{ctx.account}'"
    ), message

    listed = ecr.describe_repositories()["repositories"]
    assert all(r["repositoryName"] != missing for r in listed), (
        f"{missing} must not be implicitly created by the rejected call"
    )

    ecr.create_repository(
        repositoryName=missing,
        tags=[{"Key": "sim2real-behav", "Value": "ecr-absent-preview"}],
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=missing, force=True))

    started = ecr.start_lifecycle_policy_preview(
        repositoryName=missing, lifecyclePolicyText=policy_text
    )
    assert started["status"] in ("IN_PROGRESS", "COMPLETE"), (
        f"identical call must succeed once {missing} exists, got status={started['status']!r}"
    )

    preview = ecr.get_lifecycle_policy_preview(repositoryName=missing)
    assert preview["status"] in ("IN_PROGRESS", "COMPLETE"), (
        f"expected a retrievable preview via an independent read, got status={preview['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
