"""repository-policy-round-trip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _client_error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]

CHECK = "repository-policy-round-trip"
GROUP = 'repository-policy'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetRepositoryPolicy/GetRepositoryPolicy round-trip the policy semantically (ECR re-serializes
    the document); after DeleteRepositoryPolicy, Get and a second delete fail with
    RepositoryPolicyNotFoundException."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name, tags=[{"Key": "sim2real", "Value": CHECK}])
    # The account's own principal: the round trip needs a real grant, not a public one.
    own_root = f"arn:aws:iam::{ctx.account}:root"
    policy_text = (
        '{"Version":"2012-10-17","Statement":[{"Sid":"AllowPull","Effect":"Allow",'
        f'"Principal":{{"AWS":"{own_root}"}},"Action":"ecr:GetDownloadUrlForLayer"}}]}}'
    )
    resp = ecr.set_repository_policy(repositoryName=name, policyText=policy_text)
    assert resp["repositoryName"] == name, f"expected repositoryName {name!r}, got {resp['repositoryName']!r}"

    got = ecr.get_repository_policy(repositoryName=name)
    assert got["repositoryName"] == name, f"expected repositoryName {name!r}, got {got['repositoryName']!r}"
    doc = json.loads(got["policyText"])
    assert doc["Version"] == "2012-10-17", f"expected Version 2012-10-17, got {doc.get('Version')!r}"
    stmts = doc["Statement"]
    if isinstance(stmts, dict):
        stmts = [stmts]
    stmt = next(s for s in stmts if s.get("Sid") == "AllowPull")
    assert stmt["Effect"] == "Allow", f"expected Effect Allow, got {stmt.get('Effect')!r}"
    actions = stmt["Action"]
    if isinstance(actions, str):
        actions = [actions]
    assert "ecr:GetDownloadUrlForLayer" in actions, f"expected ecr:GetDownloadUrlForLayer in {actions!r}"
    principal = stmt["Principal"]
    if isinstance(principal, dict):
        principal = principal.get("AWS")
    assert principal in (own_root, [own_root]), f"unexpected principal: {stmt['Principal']}"

    delete_resp = ecr.delete_repository_policy(repositoryName=name)
    assert json.loads(delete_resp["policyText"]) == doc, (
        f"expected DeleteRepositoryPolicy to return the removed policy {doc!r}, "
        f"got {delete_resp['policyText']!r}"
    )
    code, message = _client_error(lambda: ecr.get_repository_policy(repositoryName=name))
    assert code == "RepositoryPolicyNotFoundException", f"expected RepositoryPolicyNotFoundException, got {code}"
    assert message == (
        f"Repository policy does not exist for the repository with name '{name}' "
        f"in the registry with id '{ctx.account}'"
    ), message

    code_redelete, message_redelete = _client_error(
        lambda: ecr.delete_repository_policy(repositoryName=name)
    )
    assert code_redelete == "RepositoryPolicyNotFoundException", (
        f"expected re-deleting an already-cleared policy to raise RepositoryPolicyNotFoundException, got {code_redelete}"
    )
    assert message_redelete == (
        f"Repository policy does not exist for the repository with name '{name}' "
        f"in the registry with id '{ctx.account}'"
    ), message_redelete

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
