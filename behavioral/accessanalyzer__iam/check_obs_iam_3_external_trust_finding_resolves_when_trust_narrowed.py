"""obs-iam-3-external-trust-finding-resolves-when-trust-narrowed."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "obs-iam-3-external-trust-finding-resolves-when-trust-narrowed"
GROUP = "cross-service"
SERVICES = ["accessanalyzer", "iam"]

#: The external principal is an IAM OIDC provider for a Cognito user pool the check creates.
#: IAM refuses an account principal that does not exist (a documentation id such as
#: 111122223333 is MalformedPolicyDocument "Invalid principal in policy"), and Access Analyzer
#: reports a role trusting an identity provider as external access, so no third party's
#: account is named.

_FINDING_BUDGET_S = 600.0
_RESOLVE_BUDGET_S = 600.0
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


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:e2e", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """A role trusting an external identity provider yields one ACTIVE external-access finding;
    narrowing its trust to this account moves that same finding to RESOLVED (retained, not
    deleted), and a role trusting only this account's root never gets a finding."""
    iam = ctx.client("iam")
    aa = ctx.client("accessanalyzer")
    account = ctx.client("sts").get_caller_identity()["Account"]
    tag = [{"Key": "sim2real", "Value": CHECK}]
    external = _federated_provider(ctx, iam, tag)

    ext_name = ctx.unique_name("sim2real-xsvc-aa-ext-")
    ext_arn = iam.create_role(
        RoleName=ext_name,
        AssumeRolePolicyDocument=_trust({"Federated": external}, "sts:AssumeRoleWithWebIdentity"),
        Description="sim2real-xsvc access analyzer external trust",
        Tags=tag,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ext_name))

    ctl_name = ctx.unique_name("sim2real-xsvc-aa-ctl-")
    ctl_arn = iam.create_role(
        RoleName=ctl_name,
        AssumeRolePolicyDocument=_trust({"AWS": f"arn:aws:iam::{account}:root"}),
        Description="sim2real-xsvc access analyzer same-account control",
        Tags=tag,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ctl_name))

    # Both roles exist before the analyzer, so its initial scan alone must find the external
    # trust; no StartResourceScan or access preview is used.
    analyzer_name = ctx.unique_name("sim2real-xsvc-aa-")
    analyzer_arn = aa.create_analyzer(
        analyzerName=analyzer_name, type="ACCOUNT", tags={"sim2real": CHECK}
    )["arn"]
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=analyzer_name))
    status = _poll_analyzer_active(aa, analyzer_name)
    assert status == "ACTIVE", f"analyzer {analyzer_name!r} ended in status {status!r}, not ACTIVE"

    findings = _poll_findings(aa, analyzer_arn, ext_arn, _FINDING_BUDGET_S)
    assert findings, (
        f"no finding for {ext_arn!r} (trusts {external}) within {_FINDING_BUDGET_S:.0f}s"
    )
    active = [f for f in findings if f["status"] == "ACTIVE"]
    assert len(active) == 1 and len(findings) == 1, (
        f"expected exactly one ACTIVE finding for the role, got "
        f"{[(f['id'], f['status']) for f in findings]!r}"
    )
    finding = active[0]
    finding_id = finding["id"]
    assert finding["resource"] == ext_arn, f"finding resource {finding['resource']!r} != {ext_arn!r}"
    assert finding["resourceType"] == "AWS::IAM::Role", (
        f"resourceType {finding['resourceType']!r}, expected 'AWS::IAM::Role'"
    )
    assert finding["isPublic"] is False, f"isPublic {finding['isPublic']!r} for a federated principal"
    assert finding.get("principal") == {"Federated": external}, (
        f"principal {finding.get('principal')!r}, expected {{'Federated': {external!r}}}"
    )
    assert finding.get("action") == ["sts:AssumeRoleWithWebIdentity"], (
        f"action {finding.get('action')!r}, expected ['sts:AssumeRoleWithWebIdentity']"
    )
    assert finding.get("resourceOwnerAccount") == account, (
        f"resourceOwnerAccount {finding.get('resourceOwnerAccount')!r} != {account!r}"
    )

    analyzed = _poll_analyzed(aa, analyzer_arn, ctl_arn, _FINDING_BUDGET_S)
    assert analyzed is not None, (
        f"control role {ctl_arn!r} was never analyzed within {_FINDING_BUDGET_S:.0f}s"
    )
    assert analyzed["isPublic"] is False and not analyzed.get("actions"), (
        f"same-account control analyzed as shared: {analyzed!r}"
    )
    ctl_findings = _list_findings(aa, analyzer_arn, ctl_arn)
    assert ctl_findings == [], (
        f"a role trusting only this account's root produced findings: {ctl_findings!r}"
    )

    iam.update_assume_role_policy(
        RoleName=ext_name, PolicyDocument=_trust({"AWS": f"arn:aws:iam::{account}:root"})
    )
    last = _poll_finding_status(aa, analyzer_arn, finding_id, "RESOLVED", _RESOLVE_BUDGET_S)
    assert last == "RESOLVED", (
        f"finding {finding_id!r} still {last!r} {_RESOLVE_BUDGET_S:.0f}s after the trust policy "
        "was narrowed to this account"
    )
    after = _list_findings(aa, analyzer_arn, ext_arn)
    assert [(f["id"], f["status"]) for f in after] == [(finding_id, "RESOLVED")], (
        f"after narrowing, the role's findings were {[(f['id'], f['status']) for f in after]!r}; "
        f"expected the same finding {finding_id!r} retained as RESOLVED, not deleted or replaced"
    )

    ctl_after = _list_findings(aa, analyzer_arn, ctl_arn)
    assert ctl_after == [], f"control role acquired findings later: {ctl_after!r}"


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


def _poll_finding_status(aa, analyzer_arn: str, finding_id: str, want: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = aa.get_finding(analyzerArn=analyzer_arn, id=finding_id)["finding"]["status"]
        if status == want:
            return status
        time.sleep(_POLL_S)
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
