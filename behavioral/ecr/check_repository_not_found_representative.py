"""repository-not-found-representative."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _client_error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

CHECK = "repository-not-found-representative"
GROUP = 'error-semantics'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRepositoryPolicy on a nonexistent repository is refused RepositoryNotFoundException
    with the exact message, while a repository with a policy set returns it."""
    ecr = ctx.client("ecr")

    name = ctx.unique_name("sim2real-behav-ecr-")
    ecr.create_repository(repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPull",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.client('sts').get_caller_identity()['Account']}:root"},
                "Action": "ecr:BatchGetImage",
            }
        ],
    }
    ecr.set_repository_policy(repositoryName=name, policyText=json.dumps(policy))
    resp = ecr.get_repository_policy(repositoryName=name)
    assert resp["repositoryName"] == name, f"expected {name}, got {resp['repositoryName']!r}"
    assert json.loads(resp["policyText"]) == policy, "policy text does not round-trip"

    bogus = ctx.unique_name("sim2real-behav-ecr-nonexistent-")
    code, message = _client_error(lambda: ecr.get_repository_policy(repositoryName=bogus))
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
    assert message == (
        f"The repository with name '{bogus}' does not exist in the registry with id "
        f"'{ctx.account}'"
    ), message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
