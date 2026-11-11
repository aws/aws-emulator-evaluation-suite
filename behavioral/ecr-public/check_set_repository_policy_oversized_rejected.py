"""set-repository-policy-oversized-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-repository-policy-oversized-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr-public"]

_MAX_POLICY_CHARS = 10240  # SetRepositoryPolicy policyText max length, per
# https://docs.aws.amazon.com/AmazonECRPublic/latest/APIReference/API_SetRepositoryPolicy.html


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A syntactically valid but oversized (>10240 char) repository policy document is
    rejected by SetRepositoryPolicy rather than being stored and truncated."""
    ecrpublic = _ecrpublic(ctx)
    name = ctx.unique_name("sim2real-behav-ecrpub-bigpol-")
    ecrpublic.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: ecrpublic.delete_repository(repositoryName=name, force=True))

    padding = "x" * (_MAX_POLICY_CHARS + 200)
    oversized_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowPull",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["ecr-public:BatchGetImage", "ecr-public:GetDownloadUrlForLayer"],
                },
                {
                    "Sid": "Padding",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "ecr-public:DescribeRepositories",
                    "Condition": {"StringEquals": {"aws:PrincipalTag/pad": padding}},
                },
            ],
        }
    )
    assert len(oversized_policy) > _MAX_POLICY_CHARS, (
        f"test setup bug: policy is only {len(oversized_policy)} chars, "
        f"needs to exceed {_MAX_POLICY_CHARS}"
    )

    # boto3's bundled model would itself reject an oversized policyText client-side before it
    # ever reaches the wire (the shape declares the same 10240-char max_length), which would
    # only test botocore's shared model rather than the target service. Disable client-side
    # parameter validation so the request actually reaches the server.
    unvalidated = _client_without_param_validation(ctx, "ecr-public")
    err = _error(
        lambda: unvalidated.set_repository_policy(repositoryName=name, policyText=oversized_policy)
    )
    expected = ("InvalidParameterException", "Invalid parameter at 'PolicyText' failed to satisfy constraint: 'Must have length less than or equal to 10240'")
    assert (err.get("Code"), err.get("Message")) == expected, (
        f"expected {expected} for an oversized policyText, got {err!r}"
    )

    # Effect absent: no policy got stored (not even a truncated fragment of it).
    err = _error(lambda: ecrpublic.get_repository_policy(repositoryName=name))
    expected = (
        "RepositoryPolicyNotFoundException",
        f"Repository policy does not exist for the repository with name '{name}' in the registry with id '{ctx.account}'",
    )
    assert (err.get("Code"), err.get("Message")) == expected, (
        f"rejected oversized policy must leave no stored policy behind {expected}, got {err!r}"
    )

    # Positive control: an ordinary, within-limit policy is accepted and persisted verbatim.
    small_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowPull",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["ecr-public:BatchGetImage", "ecr-public:GetDownloadUrlForLayer"],
                }
            ],
        }
    )
    ecrpublic.set_repository_policy(repositoryName=name, policyText=small_policy)
    stored = ecrpublic.get_repository_policy(repositoryName=name)["policyText"]
    assert json.loads(stored) == json.loads(small_policy), (
        f"within-limit policy must round-trip verbatim: stored={stored!r} expected={small_policy!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _client_without_param_validation(ctx, service):
    """A client on the same target with botocore's client-side validation off, so the request
    reaches the server."""
    from botocore.config import Config

    return ctx.client(service, region="us-east-1", config=Config(parameter_validation=False))


def _ecrpublic(ctx):
    """ecr-public's control-plane API is served only from us-east-1, so pin that region on the
    target ctx names."""
    from botocore.config import Config

    return ctx.client("ecr-public", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"}))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
