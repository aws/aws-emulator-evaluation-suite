"""lifecycle-policy-round-trip."""
from __future__ import annotations

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
    kwargs.setdefault("tags", [{"Key": "sim2real:managed", "Value": "true"}])
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]

CHECK = "lifecycle-policy-round-trip"
GROUP = 'lifecycle-policy'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutLifecyclePolicy/GetLifecyclePolicy round-trip the policy text; DeleteLifecyclePolicy
    removes it, and a subsequent Get MUST fail with LifecyclePolicyNotFoundException."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name)
    policy_text = (
        '{"rules":[{"rulePriority":1,"description":"expire old",'
        '"selection":{"tagStatus":"untagged","countType":"imageCountMoreThan","countNumber":5},'
        '"action":{"type":"expire"}}]}'
    )
    ecr.put_lifecycle_policy(repositoryName=name, lifecyclePolicyText=policy_text)

    got = ecr.get_lifecycle_policy(repositoryName=name)
    assert got["lifecyclePolicyText"] == policy_text, (
        f"expected GetLifecyclePolicy to echo back the text set via Put, got {got['lifecyclePolicyText']!r}"
    )

    ecr.delete_lifecycle_policy(repositoryName=name)
    code, message = _error(lambda: ecr.get_lifecycle_policy(repositoryName=name))
    assert code == "LifecyclePolicyNotFoundException", f"expected LifecyclePolicyNotFoundException, got {code}"
    assert message == (
        f"Lifecycle policy does not exist for the repository with name '{name}' in the registry with id '{ctx.account}'"
    ), message

    code_again, message_again = _error(lambda: ecr.delete_lifecycle_policy(repositoryName=name))
    assert code_again == "LifecyclePolicyNotFoundException", (
        f"expected a second delete on an already-deleted policy to also raise "
        f"LifecyclePolicyNotFoundException, got {code_again}"
    )
    assert message_again == (
        f"Lifecycle policy does not exist for the repository with name '{name}' in the registry with id '{ctx.account}'"
    ), message_again

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
