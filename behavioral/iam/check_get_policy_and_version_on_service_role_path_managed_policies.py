"""get-policy-and-version-on-service-role-path-managed-policies."""

from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "get-policy-and-version-on-service-role-path-managed-policies"
GROUP = "managed-policies"
SERVICES = ["iam"]

_POLICY_NAMES = ("AmazonAppStreamServiceAccess", "AWSLambdaBasicExecutionRole")


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPolicy on an AWS managed policy under the /service-role/ path returns its fixed ARN, that
    path and an attachable policy; GetPolicyVersion on its default version returns a document whose
    every statement has an Allow or Deny effect and an action."""
    iam = ctx.client("iam")

    by_name = {}
    for page in iam.get_paginator("list_policies").paginate(
        Scope="AWS", PathPrefix="/service-role/"
    ):
        for p in page["Policies"]:
            by_name[p["PolicyName"]] = p["Arn"]
    missing = set(_POLICY_NAMES) - set(by_name)
    assert not missing, f"ListPolicies(Scope=AWS, PathPrefix=/service-role/) is missing {missing}"

    for name in _POLICY_NAMES:
        arn = by_name[name]
        partition = arn.split(":")[1]
        assert arn == f"arn:{partition}:iam::aws:policy/service-role/{name}", (
            f"ListPolicies Arn for {name!r}: {arn!r}"
        )
        policy = iam.get_policy(PolicyArn=arn)["Policy"]
        assert policy["PolicyName"] == name, (
            f"GetPolicy({arn!r}) PolicyName {policy['PolicyName']!r}"
        )
        assert policy["Arn"] == arn, f"GetPolicy({arn!r}) answered for {policy['Arn']!r}"
        assert policy["Path"] == "/service-role/", f"GetPolicy({arn!r}) Path {policy['Path']!r}"
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
        assert isinstance(statements, list) and len(statements) >= 1, (
            f"default version of {arn!r} has no statement list: {statements!r}"
        )
        shapes = [(s.get("Effect") in ("Allow", "Deny"), "Action" in s) for s in statements]
        assert shapes == [(True, True)] * len(statements), (
            f"default version of {arn!r}: every statement needs an Allow/Deny Effect and an "
            f"Action, got {statements!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
