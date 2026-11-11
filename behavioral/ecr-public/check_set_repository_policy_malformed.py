"""set-repository-policy-malformed."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-repository-policy-malformed"
GROUP = 'overly-permissive'
SERVICES = ['ecr-public']

def _err(fn):
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)

    def _cleanup():
        try:
            ecr.delete_repository(repositoryName=name, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return name, resp


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetRepositoryPolicy with non-JSON policyText is refused InvalidParameterException with the
    exact message and the valid policy set before still reads back unchanged; after
    DeleteRepository, describe is refused RepositoryNotFoundException."""
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)

    # Positive control: a well-formed policy is accepted, so a target that rejects every
    # SetRepositoryPolicy call cannot be mistaken for one that specifically rejects malformed JSON.
    valid_policy_text = (
        '{"Version":"2012-10-17","Statement":[{"Sid":"AllowPull","Effect":"Allow",'
        '"Principal":"*","Action":"ecr-public:BatchCheckLayerAvailability"}]}'
    )
    valid_policy = json.loads(valid_policy_text)
    set_resp = ecr.set_repository_policy(repositoryName=name, policyText=valid_policy_text)
    assert json.loads(set_resp["policyText"]) == valid_policy, (
        f"positive control failed: expected {valid_policy}, got {set_resp.get('policyText')!r}"
    )

    err = _err(
        lambda: ecr.set_repository_policy(repositoryName=name, policyText="this-is-not-a-json-policy")
    )
    expected = ("InvalidParameterException", "Invalid parameter at 'PolicyText' failed to satisfy constraint: 'Invalid repository policy provided'")
    assert (err.get("Code"), err.get("Message")) == expected, f"expected {expected}, got {err}"

    # Effect absent: the malformed call must not have overwritten the previously-set policy.
    get_resp = ecr.get_repository_policy(repositoryName=name)
    assert json.loads(get_resp["policyText"]) == valid_policy, (
        f"repository policy was mutated despite the malformed SetRepositoryPolicy call: "
        f"expected {valid_policy}, got {get_resp.get('policyText')!r}"
    )

    ecr.delete_repository(repositoryName=name)

    # The delete is real: an independent read at the destination sees the repository gone.
    del_err = _err(lambda: ecr.describe_repositories(repositoryNames=[name]))
    expected = (
        "RepositoryNotFoundException",
        f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'",
    )
    assert (del_err.get("Code"), del_err.get("Message")) == expected, f"expected repo gone {expected}, got {del_err}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
