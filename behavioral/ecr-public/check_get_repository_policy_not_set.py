"""get-repository-policy-not-set."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-repository-policy-not-set"
GROUP = 'repository-policy'
SERVICES = ['ecr-public']

def _err(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real-check", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: _delete_repository_if_present(ecr, name))
    return name, resp


def _delete_repository_if_present(ecr, name):
    """Teardown: force-delete the repository, tolerating one the check already deleted."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRepositoryPolicy on a repository with no policy is refused
    RepositoryPolicyNotFoundException with the exact message, while a repository with a policy
    set returns it."""
    ecr = ctx.client("ecr-public")

    control_name, _ = _create_repository(ctx, ecr)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPull",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["ecr-public:BatchCheckLayerAvailability", "ecr-public:GetDownloadUrlForLayer"],
            }
        ],
    }
    ecr.set_repository_policy(repositoryName=control_name, policyText=json.dumps(policy))
    got = ecr.get_repository_policy(repositoryName=control_name)
    assert got["repositoryName"] == control_name, f"expected {control_name}, got {got.get('repositoryName')}"
    ecr.delete_repository(repositoryName=control_name)

    name, _ = _create_repository(ctx, ecr)

    code, code_msg = _err(lambda: ecr.get_repository_policy(repositoryName=name))
    assert code == "RepositoryPolicyNotFoundException", f"expected RepositoryPolicyNotFoundException, got {code}"
    expected_code_msg = f"Repository policy does not exist for the repository with name '{name}' in the registry with id '{ctx.account}'"
    assert code_msg == expected_code_msg, f"expected message {expected_code_msg!r}, got {code_msg!r}"

    ecr.delete_repository(repositoryName=name)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
