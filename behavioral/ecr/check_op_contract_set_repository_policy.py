"""op-contract-set-repository-policy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-set-repository-policy"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetRepositoryPolicy echoes the repository, registry id and exact policy, which
    GetRepositoryPolicy returns; a policy that locks the caller out of setting another is refused
    InvalidParameterException with the exact message and the valid policy stays."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    repo_name = ctx.unique_name("sim2real-ecr-pol-")
    ecr.create_repository(
        repositoryName=repo_name,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    valid_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPull",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
            }
        ],
    }
    valid_policy_text = json.dumps(valid_policy)

    # --- success path ---
    set_resp = ecr.set_repository_policy(
        repositoryName=repo_name, policyText=valid_policy_text
    )
    assert set_resp["repositoryName"] == repo_name, (
        f"expected repositoryName {repo_name}, got {set_resp['repositoryName']}"
    )
    assert set_resp["registryId"] == account_id, (
        f"expected registryId {account_id}, got {set_resp['registryId']}"
    )
    assert json.loads(set_resp["policyText"]) == valid_policy, (
        f"expected {valid_policy}, got {json.loads(set_resp['policyText'])}"
    )

    get_resp = ecr.get_repository_policy(repositoryName=repo_name)
    assert json.loads(get_resp["policyText"]) == valid_policy, (
        f"expected {valid_policy}, got {json.loads(get_resp['policyText'])}"
    )

    # --- error boundary: a policy that would lock the caller out is rejected without force ---
    lockout_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyEverything",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "ecr:*",
            }
        ],
    }
    code, message = _client_error(
        lambda: ecr.set_repository_policy(
            repositoryName=repo_name, policyText=json.dumps(lockout_policy)
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == (
        "You are about to set a repository policy that will prevent you from setting another one "
        "in the future. Use the force parameter to override this exception."
    ), message

    # the previously-set valid policy must be completely unaffected by the rejected call
    unchanged = ecr.get_repository_policy(repositoryName=repo_name)
    assert json.loads(unchanged["policyText"]) == valid_policy, (
        f"expected the pre-existing policy {valid_policy} to survive the rejected "
        f"call unchanged, got {json.loads(unchanged['policyText'])}"
    )


def _client_error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
