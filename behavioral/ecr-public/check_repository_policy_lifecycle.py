"""repository-policy-lifecycle."""
from __future__ import annotations

import json as _json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "repository-policy-lifecycle"
GROUP = 'repository-policy'
SERVICES = ['ecr-public']

def _err(fn):
    """Call fn(); return the botocore Error (Code and Message) if a ClientError is raised. An
    unexpected SUCCESS raises, so a target that accepts what AWS refuses cannot read as a code
    mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_repository_if_present(ecr, name):
    """Teardown: force-delete the repository, tolerating one the check already deleted in-band."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_repository_if_present(ecr, name))
    return name, resp


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetRepositoryPolicy attaches a policy; GetRepositoryPolicy reflects it; DeleteRepositoryPolicy removes it and Get then 404s."""
    # ecr-public's control-plane API is served only from us-east-1; pin it explicitly
    # rather than relying on the caller's configured region.
    ecr = ctx.client("ecr-public", region="us-east-1")
    name, resp = _create_repository(ctx, ecr)
    repo_arn = resp["repository"]["repositoryArn"]
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

    ecr.set_repository_policy(repositoryName=name, policyText=_json.dumps(policy))

    got = ecr.get_repository_policy(repositoryName=name)
    assert got["repositoryName"] == name
    got_policy = _json.loads(got["policyText"])
    assert got_policy["Statement"][0]["Sid"] == "AllowPull", (
        f"expected the set statement's Sid to round-trip, got {got_policy!r}"
    )

    ecr.delete_repository_policy(repositoryName=name)

    error = _err(lambda: ecr.get_repository_policy(repositoryName=name))
    assert error["Code"] == "RepositoryPolicyNotFoundException", (
        f"expected RepositoryPolicyNotFoundException, got {error!r}"
    )
    expected = (
        f"Repository policy does not exist for the repository with name '{name}' in the "
        f"registry with id '{ctx.account}'"
    )
    assert error["Message"] == expected, f"{error['Message']!r} != {expected!r}"

    ecr.delete_repository(repositoryName=name)
    _ = repo_arn

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
