"""op-contract-put-lifecycle-policy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-put-lifecycle-policy"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutLifecyclePolicy: success path echoes exact text and round-trips via GetLifecyclePolicy;
    an invalid-JSON policy is rejected with InvalidParameterException and leaves the
    previously-set valid policy completely unchanged."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    repo_name = ctx.unique_name("sim2real-ecr-lc-")
    ecr.create_repository(
        repositoryName=repo_name,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

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

    # --- success path ---
    put_resp = ecr.put_lifecycle_policy(
        repositoryName=repo_name, lifecyclePolicyText=valid_policy
    )
    assert put_resp["repositoryName"] == repo_name, (
        f"expected repositoryName {repo_name!r}, got {put_resp.get('repositoryName')!r}"
    )
    assert put_resp["registryId"] == account_id, (
        f"expected registryId {account_id!r}, got {put_resp.get('registryId')!r}"
    )
    # AWS round-trips the policy text semantically (it may reformat/reorder the
    # JSON on the server side), so compare parsed structures rather than the raw
    # string bytes.
    put_text = json.loads(put_resp["lifecyclePolicyText"])
    assert put_text == json.loads(valid_policy), (
        f"expected put response policy {json.loads(valid_policy)!r}, got {put_text!r}"
    )

    get_resp = ecr.get_lifecycle_policy(repositoryName=repo_name)
    assert get_resp["repositoryName"] == repo_name, (
        f"expected repositoryName {repo_name!r}, got {get_resp.get('repositoryName')!r}"
    )
    get_text = json.loads(get_resp["lifecyclePolicyText"])
    assert get_text == json.loads(valid_policy), (
        f"expected get response policy {json.loads(valid_policy)!r}, got {get_text!r}"
    )

    # --- error boundary: malformed JSON policy text is rejected ---
    # lifecyclePolicyText has a server-side minimum length constraint (100 chars),
    # so pad the malformed text well past that threshold to ensure the failure
    # is due to invalid JSON content (InvalidParameterException) rather than a
    # client-side ParamValidationError for being too short.
    malformed_policy = "{not valid json,,," + ("x" * 200)
    code, message = _client_error(
        lambda: ecr.put_lifecycle_policy(
            repositoryName=repo_name, lifecyclePolicyText=malformed_policy
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_message = (
        "Invalid parameter at 'LifecyclePolicyText' failed to satisfy constraint: "
        "'Lifecycle policy parsing failure: Could not map policyString into LifecyclePolicy.'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the previously-set valid policy must be completely unaffected by the rejected call
    unchanged = ecr.get_lifecycle_policy(repositoryName=repo_name)
    unchanged_text = json.loads(unchanged["lifecyclePolicyText"])
    assert unchanged_text == json.loads(valid_policy), (
        f"expected the previously-set policy {json.loads(valid_policy)!r} to survive the "
        f"rejected PutLifecyclePolicy call unchanged, got {unchanged_text!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
