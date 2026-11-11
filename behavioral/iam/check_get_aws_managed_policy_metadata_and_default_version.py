"""get-aws-managed-policy-metadata-and-default-version."""

from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-aws-managed-policy-metadata-and-default-version"
GROUP = "managed-policies"
SERVICES = ["iam"]

_POLICY_NAMES = ("ReadOnlyAccess", "AmazonDynamoDBReadOnlyAccess")
_ABSENT_POLICY_NAME = "Sim2realNoSuchManagedPolicy"


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


def _error(fn):
    """(code, message) of the refused call; an unexpected success is a failure."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


@tags(
    "axis:happy-path",
    "cap:c5",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """GetPolicy on AWS managed policies returns their name, ARN, path and default version.

    The default version is vN with a 2012-10-17 document; an absent AWS-owned name is NoSuchEntity.
    """
    iam = ctx.client("iam")
    partition = _partition(ctx)

    for name in _POLICY_NAMES:
        arn = f"arn:{partition}:iam::aws:policy/{name}"
        policy = iam.get_policy(PolicyArn=arn)["Policy"]
        assert policy["PolicyName"] == name, (
            f"GetPolicy({arn!r}) PolicyName {policy['PolicyName']!r}"
        )
        assert policy["Arn"] == arn, f"GetPolicy({arn!r}) answered for {policy['Arn']!r}"
        assert policy["Path"] == "/", f"GetPolicy({arn!r}) Path {policy['Path']!r}"
        assert policy["IsAttachable"] is True, (
            f"GetPolicy({arn!r}) IsAttachable {policy['IsAttachable']!r}"
        )
        assert re.fullmatch(r"ANPA[A-Z0-9]{17}", policy["PolicyId"]), (
            f"GetPolicy({arn!r}) PolicyId {policy['PolicyId']!r}"
        )
        default_version = policy["DefaultVersionId"]
        assert re.fullmatch(r"v[1-9][0-9]*", default_version), (
            f"GetPolicy({arn!r}) DefaultVersionId {default_version!r}"
        )

        version = iam.get_policy_version(PolicyArn=arn, VersionId=default_version)["PolicyVersion"]
        assert version["VersionId"] == default_version, (
            f"GetPolicyVersion({arn!r}) answered version {version['VersionId']!r}"
        )
        assert version["IsDefaultVersion"] is True, (
            f"GetPolicyVersion({arn!r}) IsDefaultVersion {version['IsDefaultVersion']!r}"
        )
        document = version["Document"]
        assert document["Version"] == "2012-10-17", (
            f"default version of {arn!r} has policy language version {document['Version']!r}"
        )
        statements = document["Statement"]
        assert isinstance(statements, list) and statements, (
            f"default version of {arn!r} has no statements: {statements!r}"
        )

    absent_arn = f"arn:{partition}:iam::aws:policy/{_ABSENT_POLICY_NAME}"
    code, message = _error(lambda: iam.get_policy(PolicyArn=absent_arn))
    assert (code, message) == ("NoSuchEntity", f"Policy {absent_arn} was not found."), (
        f"GetPolicy({absent_arn!r}) gave {(code, message)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
