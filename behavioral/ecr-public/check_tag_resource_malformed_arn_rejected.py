"""tag-resource-malformed-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr-public"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with an ARN whose service segment is iam instead of ecr-public is rejected with
    InvalidParameterException, and the real repository's tags are unaffected."""
    ecrp = _regional_client(ctx, "ecr-public")

    repo_name = ctx.unique_name("sim2real-behav-").lower()
    repo = ecrp.create_repository(repositoryName=repo_name)["repository"]
    ctx.on_cleanup(lambda: ecrp.delete_repository(repositoryName=repo_name, force=True))
    real_arn = repo["repositoryArn"]
    assert ":ecr-public:" in real_arn, f"unexpected ARN shape: {real_arn}"

    ecrp.tag_resource(resourceArn=real_arn, tags=[{"Key": "Environment", "Value": "prod"}])
    tags = ecrp.list_tags_for_resource(resourceArn=real_arn)["tags"]
    assert tags == [{"Key": "Environment", "Value": "prod"}], f"unexpected tags after control: {tags}"

    malformed_arn = real_arn.replace(":ecr-public:", ":iam:")
    assert malformed_arn != real_arn, f"substitution did not change the ARN: {real_arn}"

    err = _error(
        lambda: ecrp.tag_resource(
            resourceArn=malformed_arn, tags=[{"Key": "ShouldNotApply", "Value": "x"}]
        )
    )
    expected = ("InvalidParameterException", "Invalid parameter at 'resourceArn' failed to satisfy constraint: 'Unable to parse ARN'")
    assert (err.get("Code"), err.get("Message")) == expected, f"expected {expected}, got {err}"

    tags_after = ecrp.list_tags_for_resource(resourceArn=real_arn)["tags"]
    assert tags_after == [{"Key": "Environment", "Value": "prod"}], (
        f"malformed-ARN call had an observable side effect on the real repository: {tags_after}"
    )


def _regional_client(ctx, service: str, region: str = "us-east-1"):
    """ecr-public is served only from us-east-1, so pin that region."""
    from botocore.config import Config

    return ctx.client(service, region=region, config=Config(retries={"max_attempts": 8, "mode": "standard"}))


def _error(fn):
    """Return the botocore Error dict from fn(); raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"malformed ARN was accepted instead of rejected: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
