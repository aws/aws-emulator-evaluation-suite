"""set-repository-policy-invalid-effect-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "set-repository-policy-invalid-effect-rejected"
GROUP = "server-side"
SERVICES = ["ecr-public"]


def _ecrpub_client(ctx):
    """ecr-public's control-plane API is served only from us-east-1, so pin that region."""
    from botocore.config import Config

    return ctx.client("ecr-public", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"}))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetRepositoryPolicy rejects an Effect outside {Allow, Deny} with InvalidParameterException and
    stores no policy; the same statement with Effect Allow succeeds and round-trips.
    """
    ecr = _ecrpub_client(ctx)
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-ecrp-lockout-")
    ecr.create_repository(repositoryName=name)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))

    def _policy(effect: str) -> dict:
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "CrossAccountPull",
                    "Effect": effect,
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": ["ecr-public:BatchCheckLayerAvailability"],
                }
            ],
        }

    invalid_policy = _policy("Permit")  # not a valid IAM Effect value
    invalid_text = json.dumps(invalid_policy)

    err = _error(
        lambda: ecr.set_repository_policy(repositoryName=name, policyText=invalid_text)
    )
    expected = ("InvalidParameterException", "Invalid parameter at 'PolicyText' failed to satisfy constraint: 'Invalid repository policy provided'")
    assert (err.get("Code"), err.get("Message")) == expected, (
        f"expected {expected} for an Effect outside {{Allow, Deny}}, got {err!r}"
    )

    # effect absent: the rejected policy must not have persisted
    no_policy = _error(lambda: ecr.get_repository_policy(repositoryName=name))
    expected = (
        "RepositoryPolicyNotFoundException",
        f"Repository policy does not exist for the repository with name '{name}' in the registry with id '{ctx.account}'",
    )
    assert (no_policy.get("Code"), no_policy.get("Message")) == expected, (
        f"expected no policy persisted after the rejected SetRepositoryPolicy {expected}, got {no_policy!r}"
    )

    # positive control: the byte-identical statement with a valid Effect succeeds.
    # AWS normalizes a single-element Action array to a scalar string on read-back,
    # so compare the meaningful fields rather than requiring
    # exact JSON-structural equality.
    valid_policy = _policy("Allow")
    ecr.set_repository_policy(repositoryName=name, policyText=json.dumps(valid_policy))
    fetched = json.loads(ecr.get_repository_policy(repositoryName=name)["policyText"])
    fetched_stmt = fetched["Statement"][0]
    assert fetched_stmt["Sid"] == "CrossAccountPull", (
        f"expected Sid 'CrossAccountPull' to round-trip, got {fetched_stmt.get('Sid')!r}"
    )
    assert fetched_stmt["Effect"] == "Allow", (
        f"expected Effect 'Allow' to round-trip, got {fetched_stmt.get('Effect')!r}"
    )
    expected_principal = {"AWS": f"arn:aws:iam::{account_id}:root"}
    assert fetched_stmt["Principal"] == expected_principal, (
        f"expected Principal {expected_principal}, got {fetched_stmt.get('Principal')!r}"
    )
    fetched_actions = fetched_stmt["Action"]
    if isinstance(fetched_actions, str):
        fetched_actions = [fetched_actions]
    assert fetched_actions == ["ecr-public:BatchCheckLayerAvailability"], (
        f"expected Action ['ecr-public:BatchCheckLayerAvailability'], got {fetched_actions!r}"
    )


def _error(fn):
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
