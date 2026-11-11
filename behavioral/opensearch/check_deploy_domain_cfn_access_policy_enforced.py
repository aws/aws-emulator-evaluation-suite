"""deploy-domain-cfn-access-policy-enforced."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-domain-cfn-access-policy-enforced"
GROUP = "deploy"
SERVICES = ["opensearch"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DomainNameParam:
    Type: String
  AllowedRoleArnParam:
    Type: String
  DeniedRoleArnParam:
    Type: String
Resources:
  Domain:
    Type: AWS::OpenSearchService::Domain
    Properties:
      DomainName: !Ref DomainNameParam
      ClusterConfig:
        InstanceType: t3.small.search
        InstanceCount: 1
        DedicatedMasterEnabled: false
        ZoneAwarenessEnabled: false
      EBSOptions:
        EBSEnabled: true
        VolumeType: gp3
        VolumeSize: 10
      AccessPolicies:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Ref AllowedRoleArnParam
            Action: 'es:*'
            Resource: !Sub 'arn:${AWS::Partition}:es:${AWS::Region}:${AWS::AccountId}:domain/${DomainNameParam}/*'
          - Effect: Deny
            Principal:
              AWS: !Ref DeniedRoleArnParam
            Action: 'es:*'
            Resource: !Sub 'arn:${AWS::Partition}:es:${AWS::Region}:${AWS::AccountId}:domain/${DomainNameParam}/*'
      Tags:
        - Key: sim2real:managed
          Value: 'true'
Outputs:
  DomainArn:
    Value: !GetAtt Domain.Arn
"""

_INDEX_NAME = "sim2real-idx-acl"


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed domain access policy is enforced at the domain's REST endpoint: the role it
    explicitly denies gets 403 on a SigV4-signed read, while the allowed role writes, reads and
    searches, and the refused read leaves the document intact.
    """
    allowed_role_arn = _create_assumable_role(ctx, "allowed")
    denied_role_arn = _create_assumable_role(ctx, "denied")

    domain_name = _deploy_cfn_stack_tolerating_role_propagation(
        ctx, allowed_role_arn, denied_role_arn
    )

    base_client = ctx.client("opensearch")
    domain_status = _wait_domain_active(ctx, base_client, domain_name)
    base_url = ctx.endpoint_url(domain_status["Endpoint"])

    allowed_creds = _assume_role_credentials(ctx, allowed_role_arn)
    denied_creds = _assume_role_credentials(ctx, denied_role_arn)

    _wait_data_plane_ready(ctx, base_url, allowed_creds)

    # Retried: a freshly deployed resource policy can take a few seconds to propagate.
    status, put_body = _retry_until_status(
        lambda: _signed_request(
            ctx, "PUT", f"{base_url}/{_INDEX_NAME}/_doc/1", allowed_creds,
            body={"title": "allowed"},
        ),
        expected={200, 201},
        timeout_s=_budget_s(ctx, 120.0),
        ctx=ctx,
    )
    assert status in (200, 201), f"allowed principal's write was refused ({status}): {put_body}"
    status, refreshed = _signed_request(ctx, "POST", f"{base_url}/{_INDEX_NAME}/_refresh", allowed_creds)
    assert status == 200, f"_refresh failed ({status}): {refreshed}"

    # Signed HTTP, not the SDK: AccessPolicies gate only the REST endpoint, not the control-plane
    # index APIs. The template denies the role by name because identity-based es:* alone would
    # authorize a principal merely absent from the policy.
    status, denied_body = _signed_request(ctx, "GET", f"{base_url}/{_INDEX_NAME}/_doc/1", denied_creds)
    assert status == 403, f"denied principal's read must be refused, got {status}: {denied_body}"
    denied_text = json.dumps(denied_body).lower()
    assert any(word in denied_text for word in ("not authorized", "access denied", "forbidden")), (
        f"403 body must say the principal is not authorized, got {denied_body}"
    )

    status, control = _signed_request(ctx, "GET", f"{base_url}/{_INDEX_NAME}/_doc/1", allowed_creds)
    assert status == 200 and control.get("_source", {}).get("title") == "allowed", (
        f"document disturbed by the refused read, or the control read itself failed: "
        f"{status} {control}"
    )

    # The allowed role still works, so the denial was principal-specific, not an outage.
    status, put_body_2 = _signed_request(
        ctx, "PUT", f"{base_url}/{_INDEX_NAME}/_doc/2", allowed_creds,
        body={"title": "restated"},
    )
    assert status in (200, 201), f"allowed principal's second write was refused ({status}): {put_body_2}"
    status, refreshed_2 = _signed_request(ctx, "POST", f"{base_url}/{_INDEX_NAME}/_refresh", allowed_creds)
    assert status == 200, f"second _refresh failed ({status}): {refreshed_2}"
    status, found = _signed_request(
        ctx, "POST", f"{base_url}/{_INDEX_NAME}/_search", allowed_creds,
        # `match` is OR-across-tokens; a term shared with doc 1 would match both documents.
        body={"query": {"match": {"title": "restated"}}},
    )
    assert status == 200, f"_search failed ({status}): {found}"
    hits = found.get("hits", {}).get("hits", [])
    assert len(hits) == 1, f"expected exactly one match for the second document, got {hits}"


# ===== shared domain helpers =====


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _short_name(raw: str, max_len: int, min_len: int = 3) -> str:
    name = "".join(c for c in raw.lower() if c.isalnum() or c == "-")
    if len(name) > max_len:
        name = name[:max_len]
    name = name.rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name[1:]
    while len(name) < min_len:
        name += "0"
    return name


def _retry_until_success(fn, timeout_s: float = 60.0, interval_s: float = 1.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("a successful call: the run budget ended first; not graded") from last_err
    if last_err is not None:
        raise last_err
    raise AssertionError("retry loop exited without success or error")


def _retry_until_status(fn, expected: set[int], timeout_s: float = 60.0, interval_s: float = 1.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last: tuple[int, Any] | None = None
    while time.monotonic() < deadline:
        last = fn()
        if last[0] in expected:
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"status {expected} (last={last}): the run budget ended first; not graded")
    raise AssertionError(f"never reached status {expected} within {timeout_s}s, last={last}")


def _create_assumable_role(ctx, label: str) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name(f"sim2real-behav-aos-{label}-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="es-full-access",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "es:*", "Resource": "*"}]}
        ),
    )
    return role["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="es-full-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _assume_role_credentials(ctx, role_arn: str) -> Credentials:
    sts = ctx.client("sts")

    def _assume():
        return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")["Credentials"]

    creds = _retry_until_success(_assume, timeout_s=_budget_s(ctx, 60.0), interval_s=1.0, ctx=ctx)
    return Credentials(
        access_key=creds["AccessKeyId"],
        secret_key=creds["SecretAccessKey"],
        token=creds["SessionToken"],
    )


def _signed_request(ctx, method, url, credentials: Credentials, *, body=None):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json), signed
    with the given principal's credentials rather than the ambient ones."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(credentials, "es", ctx.region).add_auth(aws_req)
    req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}


def _wait_data_plane_ready(ctx, base_url: str, credentials: Credentials, timeout_s: float = 300.0) -> None:
    """Poll until the allowed principal stops getting 403: an active domain with an Endpoint can
    still refuse signed requests until its authorizer has the access policy."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed_request(ctx, "GET", f"{base_url}/_cluster/health", credentials)
        if status != 403:
            return
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError("the domain data plane to admit the allowed principal: the run budget ended first; not graded")
    raise AssertionError(f"domain data plane still 403 for the allowed principal after {timeout_s}s (last status {status})")


class _StackCreateFailed(Exception):
    """CreateStack settled in a failed state; carries the FAILED resource events' reasons."""


def _deploy_cfn_stack(ctx, stack_name: str, template_body: str, parameters: dict[str, str]) -> dict[str, str]:
    cfn = ctx.client("cloudformation")

    def _cleanup() -> None:
        # The domain's deletion is slow, so the stack delete is not awaited.
        cfn.delete_stack(StackName=stack_name)

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM"],
        OnFailure="DO_NOTHING",
    )
    ctx.on_cleanup(_cleanup)
    waiter = cfn.get_waiter("stack_create_complete")
    try:
        waiter.wait(
            StackName=stack_name,
            WaiterConfig={"Delay": 2, "MaxAttempts": int(_budget_s(ctx, 2400.0) / 2) + 1},
        )
    except Exception as err:
        if _budget_spent(ctx):
            raise TimeoutError(f"stack {stack_name} to create: the run budget ended first; not graded") from err
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        reasons = [
            f"{e['LogicalResourceId']}: {e.get('ResourceStatus')}: {e.get('ResourceStatusReason')}"
            for e in events
            if e.get("ResourceStatus", "").endswith("FAILED")
        ]
        raise _StackCreateFailed(f"stack {stack_name} failed to create: {reasons}") from err
    resp = cfn.describe_stacks(StackName=stack_name)
    return {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}


def _deploy_cfn_stack_tolerating_role_propagation(
    ctx, allowed_role_arn: str, denied_role_arn: str, attempts: int = 3
) -> str:
    """Deploy with fresh names per attempt: a just-created role can fail CREATE_FAILED ("Error
    setting policy") while IAM propagates it. Returns the deployed domain name."""
    last_reason = ""
    for attempt in range(attempts):
        domain_name = _short_name(ctx.unique_name("aosdxa"), 28)
        stack_name = ctx.unique_name("sim2real-behav-osacl-")
        parameters = {
            "DomainNameParam": domain_name,
            "AllowedRoleArnParam": allowed_role_arn,
            "DeniedRoleArnParam": denied_role_arn,
        }
        try:
            _deploy_cfn_stack(ctx, stack_name, _TEMPLATE, parameters)
            return domain_name
        except _StackCreateFailed as err:
            last_reason = str(err)
            if "Error setting policy" not in last_reason and "is invalid" not in last_reason:
                raise AssertionError(last_reason) from err
            if attempt < attempts - 1:
                time.sleep(20.0 * (attempt + 1))
    raise AssertionError(
        f"stack create still rejected the new role principals after {attempts} attempts: {last_reason}"
    )


def _wait_domain_active(ctx, opensearch, domain_name: str, timeout_s: float = 1800.0) -> dict[str, Any]:
    def _delete() -> None:
        try:
            opensearch.delete_domain(DomainName=domain_name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_delete)
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} to become active: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} never became active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
