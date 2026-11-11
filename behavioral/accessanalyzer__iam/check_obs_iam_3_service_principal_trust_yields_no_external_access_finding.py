"""obs-iam-3-service-principal-trust-yields-no-external-access-finding."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "obs-iam-3-service-principal-trust-yields-no-external-access-finding"
GROUP = "cross-service"
SERVICES = ["accessanalyzer", "iam"]

#: The external principal is an IAM OIDC provider for a Cognito user pool the check creates.
#: IAM refuses an account principal that does not exist (a documentation id such as
#: 111122223333 is MalformedPolicyDocument "Invalid principal in policy"), and Access Analyzer
#: reports a role trusting an identity provider as external access, so no third party's
#: account is named.

_SCAN_BUDGET_S = 600.0
_POLL_S = 2.0


def _federated_provider(ctx, iam, tag) -> str:
    """An IAM OIDC provider for a Cognito user pool the check creates: an identity outside the
    account's zone of trust that no third party owns. Returns the provider ARN."""
    cip = ctx.client("cognito-idp")
    pool_id = cip.create_user_pool(PoolName=ctx.unique_name("sim2real-xsvc-aa-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cip.delete_user_pool(UserPoolId=pool_id))
    client_id = cip.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-xsvc-aa-client-")
    )["UserPoolClient"]["ClientId"]
    arn = iam.create_open_id_connect_provider(
        Url=f"https://cognito-idp.{ctx.region}.amazonaws.com/{pool_id}",
        ClientIDList=[client_id],
        Tags=tag,
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn))
    return arn


def _trust(principal: dict, action: str = "sts:AssumeRole") -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": principal, "Action": action}],
    })


@tags("axis:negative-delivery", "cap:c7", "concern:e2e", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """A role only lambda.amazonaws.com may assume produces NO external-access finding, while a
    role trusting an external identity provider, analyzed in the same scan, does: a service
    principal is not external access."""
    iam = ctx.client("iam")
    aa = ctx.client("accessanalyzer")
    tag = [{"Key": "sim2real", "Value": CHECK}]
    external = _federated_provider(ctx, iam, tag)

    svc_name = ctx.unique_name("sim2real-xsvc-aa-svc-")
    svc_arn = iam.create_role(
        RoleName=svc_name,
        AssumeRolePolicyDocument=_trust({"Service": "lambda.amazonaws.com"}),
        Description="sim2real-xsvc access analyzer service-principal trust",
        Tags=tag,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_name))

    pos_name = ctx.unique_name("sim2real-xsvc-aa-pos-")
    pos_arn = iam.create_role(
        RoleName=pos_name,
        AssumeRolePolicyDocument=_trust({"Federated": external}, "sts:AssumeRoleWithWebIdentity"),
        Description="sim2real-xsvc access analyzer positive control",
        Tags=tag,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=pos_name))

    # Both roles exist before the analyzer, so its initial scan evaluates both; no
    # StartResourceScan or access preview is used.
    analyzer_name = ctx.unique_name("sim2real-xsvc-aa-")
    analyzer_arn = aa.create_analyzer(
        analyzerName=analyzer_name, type="ACCOUNT", tags={"sim2real": CHECK}
    )["arn"]
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=analyzer_name))
    status = _poll_analyzer_active(aa, analyzer_name)
    assert status == "ACTIVE", f"analyzer {analyzer_name!r} ended in status {status!r}, not ACTIVE"

    # The positive control's finding plus GetAnalyzedResource on the service-principal role
    # form the barrier that makes its empty finding list meaningful (instead of a sleep).
    pos = _poll_findings(aa, analyzer_arn, pos_arn, _SCAN_BUDGET_S)
    assert [(f["status"], f.get("principal")) for f in pos] == [("ACTIVE", {"Federated": external})], (
        f"positive control {pos_arn!r} (trusts {external}) produced "
        f"{[(f['status'], f.get('principal')) for f in pos]!r} within {_SCAN_BUDGET_S:.0f}s; "
        "expected one ACTIVE finding naming that provider"
    )

    analyzed = _poll_analyzed(aa, analyzer_arn, svc_arn, _SCAN_BUDGET_S)
    assert analyzed is not None, (
        f"service-principal role {svc_arn!r} was never analyzed within {_SCAN_BUDGET_S:.0f}s"
    )
    assert analyzed["resourceType"] == "AWS::IAM::Role", f"analyzed resource {analyzed!r}"
    assert analyzed["isPublic"] is False and not analyzed.get("actions"), (
        f"a lambda.amazonaws.com trust was analyzed as shared: {analyzed!r}"
    )
    svc_findings = _list_findings(aa, analyzer_arn, svc_arn)
    assert svc_findings == [], (
        f"a role trusting only lambda.amazonaws.com produced external-access findings: "
        f"{[(f['id'], f['status'], f.get('principal')) for f in svc_findings]!r}"
    )

    pos_again = _list_findings(aa, analyzer_arn, pos_arn)
    assert [f["status"] for f in pos_again] == ["ACTIVE"], (
        f"positive control's findings drifted to {[(f['id'], f['status']) for f in pos_again]!r}"
    )
    svc_again = _list_findings(aa, analyzer_arn, svc_arn)
    assert svc_again == [], f"service-principal role acquired findings later: {svc_again!r}"


def _poll_analyzer_active(aa, name: str, timeout_s: float = 120.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = "CREATING"
    while time.monotonic() < deadline:
        status = aa.get_analyzer(analyzerName=name)["analyzer"]["status"]
        if status != "CREATING":
            return status
        time.sleep(3.0)
    return status


def _list_findings(aa, analyzer_arn: str, resource_arn: str) -> list:
    out = []
    for page in aa.get_paginator("list_findings").paginate(
        analyzerArn=analyzer_arn, filter={"resource": {"eq": [resource_arn]}}
    ):
        out.extend(page["findings"])
    return out


def _poll_findings(aa, analyzer_arn: str, resource_arn: str, timeout_s: float) -> list:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        found = _list_findings(aa, analyzer_arn, resource_arn)
        if found:
            return found
        time.sleep(_POLL_S)
    return []


def _poll_analyzed(aa, analyzer_arn: str, resource_arn: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return aa.get_analyzed_resource(analyzerArn=analyzer_arn, resourceArn=resource_arn)[
                "resource"
            ]
        except aa.exceptions.ResourceNotFoundException:
            time.sleep(_POLL_S)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
