"""repository-policy-malformed-json-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "repository-policy-malformed-json-rejected"
GROUP = "representation"
SERVICES = ["ecr-public"]



def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _regional_client(ctx, service: str, region: str = "us-east-1"):
    """ecr-public is only operable in us-east-1 regardless of the harness's configured
    verify-account region. ctx.client()'s region override handles this for both real AWS
    and an emulator, so there is no need to hand-roll boto3.client() against the harness's
    private credentials."""
    return ctx.client(service, region=region)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetRepositoryPolicy rejects a syntactically invalid (non-JSON) policy document with
    InvalidParameterException, leaves the previously-set valid policy untouched, and a
    subsequent valid SetRepositoryPolicy call (the positive control) still succeeds."""
    ecrp = _regional_client(ctx, "ecr-public")
    name = ctx.unique_name("sim2real-behav-badpolicy-")
    ecrp.create_repository(
        repositoryName=name,
        tags=[{"Key": "sim2real-managed", "Value": "true"}, {"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecrp.delete_repository(repositoryName=name, force=True))

    valid_policy_text = (
        '{"Version":"2012-10-17","Statement":[{"Sid":"AllowPull","Effect":"Allow",'
        '"Principal":"*","Action":"ecr-public:BatchCheckLayerAvailability"}]}'
    )
    valid_policy = json.loads(valid_policy_text)
    set_resp = ecrp.set_repository_policy(repositoryName=name, policyText=valid_policy_text)
    # AWS may re-serialize (pretty-print) the stored policy text, so compare parsed JSON,
    # not the literal string.
    assert json.loads(set_resp["policyText"]) == valid_policy

    malformed_policy_text = "{this is not valid json at all,,,}"
    error = _error(
        lambda: ecrp.set_repository_policy(repositoryName=name, policyText=malformed_policy_text)
    )
    assert error["Code"] == "InvalidParameterException", f"unexpected error: {error!r}"
    expected = "Invalid parameter at 'PolicyText' failed to satisfy constraint: 'Invalid repository policy provided'"
    assert error["Message"] == expected, f"refusal message {error['Message']!r} != {expected!r}"

    # Effect absent: the malformed call must not have overwritten the previously-set policy.
    get_resp = ecrp.get_repository_policy(repositoryName=name)
    assert json.loads(get_resp["policyText"]) == valid_policy, (
        "repository policy was mutated despite the malformed SetRepositoryPolicy call"
    )

    # Positive control: a subsequent valid call still succeeds and takes effect.
    other_valid_policy_text = (
        '{"Version":"2012-10-17","Statement":[{"Sid":"AllowDescribe","Effect":"Allow",'
        '"Principal":"*","Action":"ecr-public:DescribeImages"}]}'
    )
    other_valid_policy = json.loads(other_valid_policy_text)
    ecrp.set_repository_policy(repositoryName=name, policyText=other_valid_policy_text)
    final_get = ecrp.get_repository_policy(repositoryName=name)
    assert json.loads(final_get["policyText"]) == other_valid_policy



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
