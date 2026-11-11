"""deploy-opensearch-1-changeset-swaps-allowed-and-denied-roles-in-place."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError, WaiterError

CHECK = "deploy-opensearch-1-changeset-swaps-allowed-and-denied-roles-in-place"
GROUP = "deploy-update"
SERVICES = ["cloudformation", "iam", "opensearch", "sts"]

# Marker for a data-plane request the published endpoint never answered.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# Two roles and one domain in ONE stack. The domain's AccessPolicies name each role through
# !GetAtt <Role>.Arn, so the domain explicitly DependsOn both. Both roles carry the SAME
# identity-based es:ESHttp* allow, so the ONLY thing separating their data-plane verdicts is the
# explicit Deny in the domain's resource policy -- which is exactly what the change set moves.
_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: sim2real deploy-opensearch-1 access-policy swap
Parameters:
  DomainName:
    Type: String
Resources:
  RoleA:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub 'arn:${AWS::Partition}:iam::${AWS::AccountId}:root'
            Action: 'sts:AssumeRole'
      Policies:
        - PolicyName: es-http
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: ['es:ESHttpGet', 'es:ESHttpHead', 'es:ESHttpPost', 'es:ESHttpPut']
                Resource: !Sub 'arn:${AWS::Partition}:es:${AWS::Region}:${AWS::AccountId}:domain/${DomainName}/*'
      Tags:
        - Key: sim2real:managed
          Value: 'true'
  RoleB:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub 'arn:${AWS::Partition}:iam::${AWS::AccountId}:root'
            Action: 'sts:AssumeRole'
      Policies:
        - PolicyName: es-http
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: ['es:ESHttpGet', 'es:ESHttpHead', 'es:ESHttpPost', 'es:ESHttpPut']
                Resource: !Sub 'arn:${AWS::Partition}:es:${AWS::Region}:${AWS::AccountId}:domain/${DomainName}/*'
      Tags:
        - Key: sim2real:managed
          Value: 'true'
  Domain:
    Type: AWS::OpenSearchService::Domain
    DependsOn:
      - RoleA
      - RoleB
    Properties:
      DomainName: !Ref DomainName
      EngineVersion: OpenSearch_2.11
      ClusterConfig:
        InstanceType: t3.small.search
        InstanceCount: 1
        DedicatedMasterEnabled: false
        ZoneAwarenessEnabled: false
      EBSOptions:
        EBSEnabled: true
        VolumeType: gp3
        VolumeSize: 10
      DomainEndpointOptions:
        EnforceHTTPS: true
        TLSSecurityPolicy: Policy-Min-TLS-1-2-2019-07
      AccessPolicies:
        Version: '2012-10-17'
        Statement:
          - Effect: __EFFECT_A__
            Principal:
              AWS: !GetAtt RoleA.Arn
            Action: 'es:*'
            Resource: !Sub 'arn:${AWS::Partition}:es:${AWS::Region}:${AWS::AccountId}:domain/${DomainName}/*'
          - Effect: __EFFECT_B__
            Principal:
              AWS: !GetAtt RoleB.Arn
            Action: 'es:*'
            Resource: !Sub 'arn:${AWS::Partition}:es:${AWS::Region}:${AWS::AccountId}:domain/${DomainName}/*'
      Tags:
        - Key: sim2real:managed
          Value: 'true'
Outputs:
  DomainArn:
    Value: !GetAtt Domain.Arn
  DomainEndpoint:
    Value: !GetAtt Domain.DomainEndpoint
  RoleAArn:
    Value: !GetAtt RoleA.Arn
  RoleBArn:
    Value: !GetAtt RoleB.Arn
"""

_INDEX = "sim2real-swap"


def _template(effect_a: str, effect_b: str) -> str:
    return _TEMPLATE.replace("__EFFECT_A__", effect_a).replace("__EFFECT_B__", effect_b)


@tags(
    "axis:rejection", "cap:c2", "cap:c3", "cap:c7",
    "concern:deploy", "concern:data-plane", "concern:negative-classes",
    "dp:endpoint", "plane:data",
)
def run(ctx) -> None:
    """A change set swapping which role the domain's AccessPolicies allow and deny is an in-place
    update: same DomainId, ARN, endpoint and stored document, with the two roles' SigV4 data-plane
    verdicts exactly reversed; deleting the stack removes the domain and both roles.
    """
    cfn = ctx.client("cloudformation")
    osc = ctx.client("opensearch")
    iam = ctx.client("iam")

    stack_id, domain_name = _create_stack_tolerating_role_propagation(ctx, cfn, osc)
    outputs = _stack_outputs(cfn, stack_id)
    for key in ("DomainArn", "DomainEndpoint", "RoleAArn", "RoleBArn"):
        assert outputs.get(key), f"stack output {key!r} missing; outputs were {outputs!r}"

    before = _wait_domain_settled(ctx, osc, domain_name)
    assert before.get("Endpoint"), f"domain published no Endpoint: {before!r}"
    assert before["ARN"] == outputs["DomainArn"], (
        f"DescribeDomain ARN {before['ARN']!r} != stack output DomainArn {outputs['DomainArn']!r}"
    )
    assert before["Endpoint"] == outputs["DomainEndpoint"], (
        f"DescribeDomain Endpoint {before['Endpoint']!r} != stack output "
        f"DomainEndpoint {outputs['DomainEndpoint']!r}"
    )
    assert before["DomainEndpointOptions"]["EnforceHTTPS"] is True, (
        f"EnforceHTTPS not applied: {before['DomainEndpointOptions']!r}"
    )
    policy = json.loads(before["AccessPolicies"])
    effects = {_principal(s): s["Effect"] for s in policy["Statement"]}
    assert effects == {outputs["RoleAArn"]: "Allow", outputs["RoleBArn"]: "Deny"}, (
        f"deployed AccessPolicies do not resolve the !GetAtt role ARNs as declared: {effects!r}"
    )

    base = ctx.endpoint_url(before["Endpoint"])
    doc_url = f"{base}/{_INDEX}/_doc/1"
    payload = {"title": "written-by-role-a", "marker": domain_name}

    creds_a = _assume(ctx, outputs["RoleAArn"])
    creds_b = _assume(ctx, outputs["RoleBArn"])
    _wait_data_plane_allows(ctx, f"{base}/_cluster/health", creds_a)

    status, body = _signed(ctx, "PUT", doc_url, creds_a, payload)
    assert status == 201, f"role A (Allow) PUT must create the document (201), got {status}: {body!r}"
    assert body.get("result") == "created", f"role A PUT result was {body.get('result')!r}: {body!r}"

    status, body = _signed(ctx, "GET", doc_url, creds_b)
    assert status == 403, f"role B (Deny) GET must be refused (403), got {status}: {body!r}"
    want = _explicit_deny(outputs["RoleBArn"], "es:ESHttpGet")
    assert body.get("Message") == want, (
        f"role B's 403 body must be the explicit-deny refusal {want!r}: {body!r}"
    )
    # Positive control: the document exists, so B's 403 was the policy.
    status, body = _signed(ctx, "GET", doc_url, creds_a)
    assert status == 200 and body.get("_source") == payload, (
        f"role A could not read back its own document ({status}): {body!r}"
    )
    version_before = body.get("_version")

    cs_name = ctx.unique_name("sim2real-swap-")
    cfn.create_change_set(
        StackName=stack_id,
        ChangeSetName=cs_name,
        TemplateBody=_template("Deny", "Allow"),
        Parameters=[{"ParameterKey": "DomainName", "UsePreviousValue": True}],
        Capabilities=["CAPABILITY_IAM"],
        ChangeSetType="UPDATE",
    )
    cs = _wait_change_set(ctx, cfn, stack_id, cs_name)
    if cs.get("Status") != "CREATE_COMPLETE":
        raise AssertionError(
            f"change set never reached CREATE_COMPLETE: {cs.get('Status')!r} {cs.get('StatusReason')!r}"
        )
    changes = _change_set_resource_changes(cfn, stack_id, cs_name)
    by_id = {c["LogicalResourceId"]: c for c in changes}
    assert set(by_id) == {"Domain"}, (
        f"only the Domain's AccessPolicies changed, but the change set touches {sorted(by_id)!r}"
    )
    domain_change = by_id["Domain"]
    assert domain_change["Action"] == "Modify", f"Domain action was {domain_change['Action']!r}"
    assert domain_change["Replacement"] == "False", (
        f"an AccessPolicies swap must not replace the domain; Replacement={domain_change['Replacement']!r}"
    )
    changed_props = {d["Target"].get("Name") for d in domain_change.get("Details", [])}
    assert "AccessPolicies" in changed_props, (
        f"change set Details do not name AccessPolicies: {domain_change.get('Details')!r}"
    )

    cfn.execute_change_set(StackName=stack_id, ChangeSetName=cs_name)
    if _wait_stack(ctx, cfn, stack_id, timeout_s=1800.0) != "UPDATE_COMPLETE":
        raise AssertionError(
            f"stack update did not complete: {_failure_reasons(cfn, stack_id)!r}"
        )

    after = _wait_domain_settled(ctx, osc, domain_name)
    for field in ("DomainId", "ARN", "Endpoint"):
        assert after.get(field) == before.get(field), (
            f"{field} changed across an in-place update: {before.get(field)!r} -> {after.get(field)!r}"
        )
    outputs_after = _stack_outputs(cfn, stack_id)
    assert outputs_after["DomainArn"] == outputs["DomainArn"], (
        f"stack output DomainArn moved: {outputs['DomainArn']!r} -> {outputs_after['DomainArn']!r}"
    )
    effects = {_principal(s): s["Effect"] for s in json.loads(after["AccessPolicies"])["Statement"]}
    assert effects == {outputs["RoleAArn"]: "Deny", outputs["RoleBArn"]: "Allow"}, (
        f"updated AccessPolicies are not the swapped document: {effects!r}"
    )

    creds_a = _assume(ctx, outputs["RoleAArn"])
    creds_b = _assume(ctx, outputs["RoleBArn"])
    # The authorizer converges after Processing=False; wait on the read-only verdicts of BOTH
    # roles so no write is ever issued under a half-propagated policy.
    _wait_verdicts(ctx, doc_url, creds_a, 403, creds_b, 200)

    status, body = _signed(ctx, "PUT", f"{base}/{_INDEX}/_doc/2", creds_a, {"title": "after-swap"})
    assert status == 403, f"role A (now Deny) PUT must be refused (403), got {status}: {body!r}"
    want = _explicit_deny(outputs["RoleAArn"], "es:ESHttpPut")
    assert body.get("Message") == want, (
        f"role A's 403 body must be the explicit-deny refusal {want!r}: {body!r}"
    )

    status, body = _signed(ctx, "GET", doc_url, creds_b)
    assert status == 200, f"role B (now Allow) GET must succeed, got {status}: {body!r}"
    assert body.get("_source") == payload, (
        f"role B did not read back the SAME document role A wrote: {body.get('_source')!r} != {payload!r}"
    )
    assert body.get("_version") == version_before, (
        f"document version moved across the in-place update: {version_before!r} -> {body.get('_version')!r}"
    )
    # A's refused PUT stored nothing.
    status, body = _signed(ctx, "GET", f"{base}/{_INDEX}/_doc/2", creds_b)
    assert status == 404 and body.get("found") is False, (
        f"role A's refused PUT left a document behind ({status}): {body!r}"
    )

    role_names = [_role_name(outputs["RoleAArn"]), _role_name(outputs["RoleBArn"])]
    cfn.delete_stack(StackName=stack_id)
    if _wait_stack(ctx, cfn, stack_id, timeout_s=1800.0) != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack delete did not complete: {_failure_reasons(cfn, stack_id)!r}"
        )
    final = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert final == "DELETE_COMPLETE", f"stack ended {final!r}, expected 'DELETE_COMPLETE'"
    code, message = _wait_domain_gone(ctx, osc, domain_name)
    assert code == "ResourceNotFoundException", (
        f"DescribeDomain after stack delete returned {code!r}, expected ResourceNotFoundException"
    )
    assert message == f"Domain not found: {domain_name}", (
        f"DescribeDomain after stack delete said {message!r}, expected "
        f"'Domain not found: {domain_name}'"
    )
    for name in role_names:
        assert _error(lambda n=name: iam.get_role(RoleName=n)) == (
            "NoSuchEntity", f"The role with name {name} cannot be found."
        ), f"stack-owned role {name!r} survived DELETE_COMPLETE"




def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; raises AssertionError if fn() succeeds."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("call unexpectedly succeeded; expected a ClientError")


def _explicit_deny(role_arn: str, action: str) -> str:
    """The domain endpoint's refusal for a role session the resource policy explicitly denies."""
    account = role_arn.split(":")[4]
    return (f"User: arn:aws:sts::{account}:assumed-role/{_role_name(role_arn)}/sim2real-os1 "
            f"is not authorized to perform: {action} with an explicit deny in a resource-based policy")


def _principal(statement: dict) -> str:
    p = statement["Principal"]["AWS"]
    return p if isinstance(p, str) else p[0]


def _role_name(role_arn: str) -> str:
    resource = role_arn.split(":", 5)[5]
    assert resource.startswith("role/"), f"not a role ARN: {role_arn!r}"
    return resource.rsplit("/", 1)[-1]


def _failure_reasons(cfn, stack_id: str) -> list[str]:
    events = cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
    return [
        f"{e['LogicalResourceId']}: {e.get('ResourceStatus')}: {e.get('ResourceStatusReason')}"
        for e in events
        if e.get("ResourceStatus", "").endswith("FAILED")
    ]


def _stack_outputs(cfn, stack_id: str) -> dict[str, str]:
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _change_set_resource_changes(cfn, stack_id: str, cs_name: str) -> list[dict]:
    changes, token = [], None
    while True:
        kw = {"StackName": stack_id, "ChangeSetName": cs_name}
        if token:
            kw["NextToken"] = token
        page = cfn.describe_change_set(**kw)
        changes += [c["ResourceChange"] for c in page.get("Changes", []) if c.get("Type") == "Resource"]
        token = page.get("NextToken")
        if not token:
            return changes


def _stack_net(ctx, cfn, osc, stack_id: str, domain_name: str):
    """Safety net registered right after CreateStack; idempotent on a stack run() already
    deleted, and a failure raises."""

    def _cleanup() -> None:
        try:
            status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
            if status == "DELETE_COMPLETE":
                return
            cfn.delete_stack(StackName=stack_id)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
            )
        except (ClientError, WaiterError) as err:
            # The stack did not delete: remove the billable domain directly, then fail.
            try:
                osc.delete_domain(DomainName=domain_name)
            except ClientError as derr:
                if derr.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise RuntimeError(f"stack {stack_id} did not delete ({err}); domain {domain_name}: {derr}") from derr
            raise RuntimeError(f"stack {stack_id} did not delete: {type(err).__name__}: {err}") from err

    return _cleanup


def _create_stack_tolerating_role_propagation(ctx, cfn, osc, attempts: int = 3):
    """OpenSearch validates the policy's principals at CreateDomain, and a role CloudFormation
    finished moments earlier can still be unknown to it ("Error setting policy" / principal
    "is invalid"). That surfaces as a resource-level CREATE_FAILED, so the retry is a fresh
    stack and domain name, never a re-issued CreateStack. Any other failure raises at once."""
    for attempt in range(attempts):
        domain_name = ctx.unique_name("sim2real-os1-")
        stack_name = ctx.unique_name("sim2real-xsvc-os1-")
        stack_id = cfn.create_stack(
            StackName=stack_name,
            TemplateBody=_template("Allow", "Deny"),
            Parameters=[{"ParameterKey": "DomainName", "ParameterValue": domain_name}],
            Capabilities=["CAPABILITY_IAM"],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["StackId"]
        ctx.on_cleanup(_stack_net(ctx, cfn, osc, stack_id, domain_name))
        status = _wait_stack(ctx, cfn, stack_id, timeout_s=2400.0)
        if status == "CREATE_COMPLETE":
            return stack_id, domain_name
        reasons = _failure_reasons(cfn, stack_id)
        text = " ".join(reasons)
        if attempt == attempts - 1 or ("Error setting policy" not in text and "is invalid" not in text):
            raise AssertionError(f"stack {stack_name} failed to create ({status}): {reasons!r}")
        time.sleep(2.0)  # backoff before the next attempt of the bounded retry
    raise AssertionError("unreachable: stack create loop exhausted")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_stack(ctx, cfn, stack_id: str, timeout_s: float) -> str:
    """Poll the stack every 2 s until it leaves *_IN_PROGRESS; returns the last status seen."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    status = ""
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS") or time.monotonic() >= deadline:
            if status.endswith("_IN_PROGRESS") and _budget_spent(ctx):
                raise TimeoutError(f"stack {stack_id} leaving {status}: "
                                   "the run budget ended first; not graded")
            return status
        time.sleep(2.0)


def _wait_change_set(ctx, cfn, stack_id: str, cs_name: str, timeout_s: float = 300.0) -> dict:
    """Poll the change set every 2 s until it is CREATE_COMPLETE or FAILED; returns the last read."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        cs = cfn.describe_change_set(StackName=stack_id, ChangeSetName=cs_name)
        if cs.get("Status") in ("CREATE_COMPLETE", "FAILED") or time.monotonic() >= deadline:
            if cs.get("Status") not in ("CREATE_COMPLETE", "FAILED") and _budget_spent(ctx):
                raise TimeoutError(f"change set {cs_name} CREATE_COMPLETE or FAILED: "
                                   "the run budget ended first; not graded")
            return cs
        time.sleep(2.0)


def _wait_domain_settled(ctx, osc, domain_name: str, timeout_s: float = 1800.0) -> dict:
    """Poll DescribeDomain until Processing is False (and an Endpoint is published)."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last
        time.sleep(2)
    detail = (
        f"domain {domain_name} still Processing={last.get('Processing')!r} "
        f"Endpoint={last.get('Endpoint')!r} after {timeout_s}s"
    )
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} settled: the run budget ended first; not graded")
    raise AssertionError(detail)


def _wait_domain_gone(ctx, osc, domain_name: str, timeout_s: float = 1200.0) -> tuple[str, str]:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} gone: the run budget ended first; not graded")
    detail = f"domain {domain_name} still described after {timeout_s}s: Deleted={last.get('Deleted')!r}"
    raise AssertionError(detail)


def _assume(ctx, role_arn: str) -> Credentials:
    """Credentials of the role ITSELF -- the verdicts under test are per-principal. Bounded
    AccessDenied retry at first use, for IAM propagation of a freshly created role."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-os1")["Credentials"]
            return Credentials(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])
        except ClientError as err:
            if err.response["Error"]["Code"] != "AccessDenied" or time.monotonic() > deadline:
                if err.response["Error"]["Code"] == "AccessDenied" and _budget_spent(ctx):
                    raise TimeoutError(f"role {role_arn} assumable: the run budget ended first; "
                                       "not graded") from err
                raise
            time.sleep(2)


def _signed(ctx, method: str, url: str, creds: Credentials, body=None):
    """SigV4 ('es') HTTPS request to the domain endpoint -> (status, parsed json)."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(creds, "es", ctx.region).add_auth(req)
    http = urllib.request.Request(url, data=data, method=method, headers=dict(req.headers))
    try:
        with urllib.request.urlopen(http, timeout=60) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"raw": raw}
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # the endpoint did not answer
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} {url} did not complete: {type(exc).__name__}: {exc}"
        ) from exc


def _wait_data_plane_allows(ctx, url: str, creds: Credentials, timeout_s: float = 600.0) -> None:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status, body = None, None
    while time.monotonic() < deadline:
        status, body = _signed(ctx, "GET", url, creds)
        if status == 200:
            return
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"allowed role getting 200 from {url}: "
                           "the run budget ended first; not graded")
    raise AssertionError(f"allowed role never got 200 from {url} in {timeout_s}s: {status} {body!r}")


def _wait_verdicts(ctx, url, creds_x, want_x, creds_y, want_y, timeout_s: float = 600.0) -> None:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    got = None
    while time.monotonic() < deadline:
        got = (_signed(ctx, "GET", url, creds_x)[0], _signed(ctx, "GET", url, creds_y)[0])
        if got == (want_x, want_y):
            return
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"data-plane verdicts {(want_x, want_y)!r}: "
                           "the run budget ended first; not graded")
    raise AssertionError(
        f"data-plane verdicts never followed the swapped policy in {timeout_s}s: "
        f"wanted {(want_x, want_y)!r}, last {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
