"""deploy-opensearch-3-fgac-secret-master-basic-auth."""
from __future__ import annotations

import base64
import json
import secrets
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-opensearch-3-fgac-secret-master-basic-auth"
GROUP = "deploy-fgac"
SERVICES = ["opensearch"]

ENGINE_VERSION = "OpenSearch_2.11"

# Marks a failure of the target's own published endpoint as a data-plane failure.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {
        "DomainNameParam": {"Type": "String"},
        "SecretNameParam": {"Type": "String"},
        "MasterUserNameParam": {"Type": "String"},
        "IngressCidrsParam": {"Type": "CommaDelimitedList"},
    },
    "Resources": {
        "MasterSecret": {
            "Type": "AWS::SecretsManager::Secret",
            "Properties": {
                "Name": {"Ref": "SecretNameParam"},
                "Description": "sim2real FGAC master credentials (deploy-opensearch-3)",
                "GenerateSecretString": {
                    "SecretStringTemplate": {
                        "Fn::Sub": '{"username": "${MasterUserNameParam}"}'
                    },
                    "GenerateStringKey": "password",
                    "PasswordLength": 32,
                    "ExcludeCharacters": "\"'@/\\:`",
                    "RequireEachIncludedType": True,
                },
                "Tags": [{"Key": "sim2real", "Value": "deploy-opensearch-3-fgac"}],
            },
        },
        "Domain": {
            "Type": "AWS::OpenSearchService::Domain",
            "Properties": {
                "DomainName": {"Ref": "DomainNameParam"},
                "EngineVersion": ENGINE_VERSION,
                "ClusterConfig": {
                    "InstanceType": "t3.small.search",
                    "InstanceCount": 1,
                    "DedicatedMasterEnabled": False,
                    "ZoneAwarenessEnabled": False,
                },
                "EBSOptions": {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
                "NodeToNodeEncryptionOptions": {"Enabled": True},
                "EncryptionAtRestOptions": {"Enabled": True},
                "DomainEndpointOptions": {
                    "EnforceHTTPS": True,
                    "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07",
                },
                "AdvancedSecurityOptions": {
                    "Enabled": True,
                    "InternalUserDatabaseEnabled": True,
                    "MasterUserOptions": {
                        # Both halves of the admin credential come from the secret through a
                        # dynamic reference: CloudFormation resolves them at provisioning time
                        # and never stores the resolved value in the template or the stack.
                        "MasterUserName": {
                            "Fn::Sub": "{{resolve:secretsmanager:${MasterSecret}:SecretString:username}}"
                        },
                        "MasterUserPassword": {
                            "Fn::Sub": "{{resolve:secretsmanager:${MasterSecret}:SecretString:password}}"
                        },
                    },
                },
                # With FGAC on, the security plugin is the authorizer: the resource policy admits
                # any caller from the runner's own addresses, so every 401/403 observed below comes
                # from the internal user database and the role mappings, never from IAM, and the
                # endpoint answers no one else.
                "AccessPolicies": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "es:*",
                        "Resource": {"Fn::Sub": "arn:${AWS::Partition}:es:${AWS::Region}:"
                                                "${AWS::AccountId}:domain/${DomainNameParam}/*"},
                        "Condition": {"IpAddress": {"aws:SourceIp": {"Ref": "IngressCidrsParam"}}},
                    }],
                },
                "Tags": [{"Key": "sim2real", "Value": "deploy-opensearch-3-fgac"}],
            },
        },
    },
    "Outputs": {
        "SecretArn": {"Value": {"Ref": "MasterSecret"}},
        "DomainEndpoint": {"Value": {"Fn::GetAtt": ["Domain", "DomainEndpoint"]}},
    },
}


@tags(
    "axis:rejection",
    "concern:deploy",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A CFN FGAC domain whose admin user comes from a Secrets Manager dynamic reference accepts
    exactly that secret on its endpoint (401 otherwise); a second internal user gets 403 on an
    unmapped index until a role mapping is added; stack deletion removes domain and secret.
    """
    cfn = ctx.client("cloudformation")
    sm = ctx.client("secretsmanager")
    osc = ctx.client("opensearch")

    base_name = ctx.unique_name("sim2real-fg-")          # 24 chars: a legal domain name
    domain_name = base_name
    stack_name = f"{base_name}-stack"
    secret_name = f"{base_name}-master"
    master_user = "sim2real" + secrets.token_hex(4)

    # Registered before the create; LIFO runs the stack delete, then the domain, then the secret.
    ctx.on_cleanup(lambda: _force_delete_secret(sm, secret_name))
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_TEMPLATE),
        Parameters=[
            {"ParameterKey": "DomainNameParam", "ParameterValue": domain_name},
            {"ParameterKey": "SecretNameParam", "ParameterValue": secret_name},
            {"ParameterKey": "MasterUserNameParam", "ParameterValue": master_user},
            {"ParameterKey": "IngressCidrsParam", "ParameterValue": ",".join(ctx.ingress_cidrs())},
        ],
        OnFailure="DO_NOTHING",
        Tags=[{"Key": "sim2real", "Value": "deploy-opensearch-3-fgac"}],
    )["StackId"]
    _wait_stack_create(cfn, stack_id, max(1, int(_budget_s(ctx, 2100.0) // 2)), ctx=ctx)

    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"stack status {stack['StackStatus']!r}"
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    assert set(outputs) == {"SecretArn", "DomainEndpoint"}, f"stack outputs {sorted(outputs)!r}"

    secret = json.loads(sm.get_secret_value(SecretId=outputs["SecretArn"])["SecretString"])
    assert sorted(secret) == ["password", "username"], f"secret keys {sorted(secret)!r}"
    assert secret["username"] == master_user, (
        f"the secret's username is {secret['username']!r}, expected the template value "
        f"{master_user!r}"
    )
    master_password = secret["password"]  # never interpolated into any message below
    assert len(master_password) == 32, f"generated password length {len(master_password)!r}"

    # The dynamic reference is stored as a reference: the resolved password appears in neither the
    # stored template nor the domain's own description.
    body = cfn.get_template(StackName=stack_id)["TemplateBody"]
    stored = body if isinstance(body, str) else json.dumps(body)
    assert "{{resolve:secretsmanager:" in stored, "stored template lost the dynamic reference"
    assert master_password not in stored, "the stored template contains the resolved password"

    status = _wait_domain_ready(osc, domain_name, _budget_s(ctx, 900.0), ctx=ctx)
    assert status["EngineVersion"] == ENGINE_VERSION, f"EngineVersion {status['EngineVersion']!r}"
    adv = status.get("AdvancedSecurityOptions", {})
    assert adv.get("Enabled") is True and adv.get("InternalUserDatabaseEnabled") is True, (
        f"AdvancedSecurityOptions {adv!r}"
    )
    assert status["NodeToNodeEncryptionOptions"].get("Enabled") is True, (
        f"NodeToNodeEncryptionOptions {status['NodeToNodeEncryptionOptions']!r}"
    )
    assert status["EncryptionAtRestOptions"].get("Enabled") is True, (
        f"EncryptionAtRestOptions {status['EncryptionAtRestOptions']!r}"
    )
    assert status["DomainEndpointOptions"].get("EnforceHTTPS") is True, (
        f"DomainEndpointOptions {status['DomainEndpointOptions']!r}"
    )
    assert status["Endpoint"] == outputs["DomainEndpoint"], (
        f"DescribeDomain endpoint {status['Endpoint']!r} != stack output "
        f"{outputs['DomainEndpoint']!r}"
    )
    assert master_password not in json.dumps(status, default=str), (
        "DescribeDomain echoes the resolved master password"
    )
    base = ctx.endpoint_url(status["Endpoint"])

    # The admin user's 200 gates every refusal: a still-initialising security plugin also 401/403s.
    code, root, _ = _wait_status(base + "/", (master_user, master_password), 200,
                                 timeout_s=_budget_s(ctx, 600.0))
    if code != 200 and _budget_spent(ctx):
        raise TimeoutError("GET / to answer 200 for the master: the run budget ended first; not graded")
    assert code == 200, f"GET / with the secret's master credentials: HTTP {code!r} {root!r}"
    version = root.get("version", {})
    assert str(version.get("number", "")).startswith("2.11."), (
        f"GET / reports version {version!r}, expected the deployed 2.11 engine"
    )
    assert version.get("distribution") == "opensearch", f"GET / version block {version!r}"

    wrong = master_password[:-1] + ("A" if master_password[-1] != "A" else "B")
    code, wrong_body, _ = _request("GET", base + "/", auth=(master_user, wrong))
    assert code == 401, f"GET / with a wrong password returned HTTP {code!r}: {wrong_body!r}"
    assert "cluster_name" not in json.dumps(wrong_body), (
        f"a 401 must not leak cluster info: {wrong_body!r}"
    )

    code, anon_body, anon_headers = _request("GET", base + "/", auth=None)
    assert code == 401, f"GET / with no Authorization returned HTTP {code!r}: {anon_body!r}"
    challenge = anon_headers.get("www-authenticate", "")
    assert challenge.lower().startswith("basic realm="), (
        f"the anonymous 401 carries WWW-Authenticate {challenge!r}, expected a Basic challenge"
    )
    assert "cluster_name" not in json.dumps(anon_body), (
        f"an anonymous 401 must not leak cluster info: {anon_body!r}"
    )

    code, account, _ = _request("GET", base + "/_plugins/_security/api/account",
                                auth=(master_user, master_password))
    assert code == 200, f"security account API for the master: HTTP {code!r} {account!r}"
    assert account.get("user_name") == master_user, (
        f"account API reports user_name {account.get('user_name')!r}, expected the resolved "
        f"master user {master_user!r}"
    )
    assert account.get("is_internal_user") is True, f"account API body {account!r}"
    assert "all_access" in (account.get("roles") or []), (
        f"the master user's roles are {account.get('roles')!r}, expected all_access among them"
    )

    index = "sim2real-fgac-unmapped"
    master = (master_user, master_password)
    code, created, _ = _request("PUT", f"{base}/{index}", auth=master, body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}}})
    assert code == 200, f"creating {index!r}: HTTP {code!r} {created!r}"
    code, indexed, _ = _request("PUT", f"{base}/{index}/_doc/1?refresh=true", auth=master,
                                body={"marker": "unmapped-doc"})
    assert code == 201, f"indexing into {index!r}: HTTP {code!r} {indexed!r}"

    second_user = "sim2realreader"
    second_password = "Bb2!" + secrets.token_urlsafe(18)
    code, made, _ = _request("PUT", f"{base}/_plugins/_security/api/internalusers/{second_user}",
                             auth=master, body={"password": second_password})
    assert code == 201, f"creating internal user {second_user!r}: HTTP {code!r} {made!r}"
    assert made.get("status") == "CREATED", f"create internal user body {made!r}"

    second = (second_user, second_password)
    # Its own authinfo 200 makes the later 403 an authorisation, not authentication, refusal.
    code, info, _ = _wait_status(f"{base}/_plugins/_security/authinfo", second, 200,
                                 timeout_s=_budget_s(ctx, 180.0))
    if code != 200 and _budget_spent(ctx):
        raise TimeoutError("the second user to authenticate: the run budget ended first; not graded")
    assert code == 200, f"the second user never authenticated: HTTP {code!r} {info!r}"
    assert info.get("user_name") == second_user, f"authinfo for the second user: {info!r}"
    assert "all_access" not in (info.get("roles") or []), (
        f"a freshly created internal user already holds all_access: {info.get('roles')!r}"
    )

    code, denied, _ = _request("POST", f"{base}/{index}/_search", auth=second,
                               body={"query": {"match_all": {}}})
    assert code == 403, (
        f"the unmapped user's _search of {index!r} returned HTTP {code!r}, expected 403: "
        f"{denied!r}"
    )
    assert _error_type(denied) == "security_exception", f"403 body {denied!r}"
    assert "no permissions for [indices:data/read/search]" in json.dumps(denied), (
        f"the 403 does not name the refused action: {denied!r}"
    )
    assert "unmapped-doc" not in json.dumps(denied), f"the 403 leaked the document: {denied!r}"

    code, seen, _ = _request("POST", f"{base}/{index}/_search", auth=master,
                             body={"query": {"match_all": {}}})
    assert code == 200, f"positive control: master _search HTTP {code!r} {seen!r}"
    assert _markers(seen) == ["unmapped-doc"], f"master reads {_markers(seen)!r}"

    role = "sim2real_reader_role"
    code, made_role, _ = _request("PUT", f"{base}/_plugins/_security/api/roles/{role}",
                                  auth=master, body={
                                      "cluster_permissions": ["cluster_composite_ops_ro"],
                                      "index_permissions": [{"index_patterns": [index],
                                                             "allowed_actions": ["read"]}]})
    assert code == 201, f"creating role {role!r}: HTTP {code!r} {made_role!r}"
    code, mapped, _ = _request("PUT", f"{base}/_plugins/_security/api/rolesmapping/{role}",
                               auth=master, body={"users": [second_user]})
    assert code == 201, f"mapping {second_user!r} to {role!r}: HTTP {code!r} {mapped!r}"
    code, allowed, _ = _wait_status(f"{base}/{index}/_search", second, 200,
                                    timeout_s=_budget_s(ctx, 180.0),
                                    method="POST", body={"query": {"match_all": {}}})
    if code != 200 and _budget_spent(ctx):
        raise TimeoutError("the mapped second user's _search to answer 200: the run budget ended first; not graded")
    assert code == 200, f"after mapping, the second user's _search: HTTP {code!r} {allowed!r}"
    assert _markers(allowed) == ["unmapped-doc"], f"after mapping it reads {_markers(allowed)!r}"

    cfn.delete_stack(StackName=stack_id)
    try:
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 1800.0) // 2))})
    except WaiterError as err:
        if _budget_spent(ctx):
            raise TimeoutError(f"stack {stack_id} to delete: the run budget ended first; not graded") from err
        raise
    final = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert final == "DELETE_COMPLETE", f"stack status after delete {final!r}"
    _wait_domain_gone(osc, domain_name, timeout_s=_budget_s(ctx, 900.0), ctx=ctx)
    gone_code, gone_message = _error_code_and_message(
        lambda: sm.describe_secret(SecretId=secret_name))
    assert (gone_code, gone_message) == (
        "ResourceNotFoundException", "Secrets Manager can't find the specified secret.",
    ), (
        f"DescribeSecret after stack delete returned {gone_code!r}: {gone_message!r}, expected "
        "ResourceNotFoundException: \"Secrets Manager can't find the specified secret.\""
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _request(method, url, *, auth, body=None):
    """HTTPS request to the domain endpoint with HTTP basic auth (or none) -> (status, json, hdrs).
    Basic auth, not SigV4: the identities under test are FGAC internal users, not IAM principals.
    """
    data = json.dumps(body).encode() if body is not None else None
    headers = {}
    if auth is not None:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            text = resp.read().decode()
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, _parse(text), hdrs
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        hdrs = {k.lower(): v for k, v in (exc.headers or {}).items()}
        return exc.code, _parse(text), hdrs
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # the published endpoint did not answer
        raise AssertionError(
            f"{DATAPLANE_MARKER}: {method} {url} did not complete: {type(exc).__name__}: {exc}"
        ) from exc


def _parse(text):
    if not text:
        return {}
    try:
        return json.loads(text)
    except ValueError:
        return {"raw": text[:500]}


def _wait_status(url, auth, want, *, timeout_s, method="GET", body=None):
    """Poll one request until it answers `want` (the observable condition), bounded."""
    deadline = time.monotonic() + timeout_s
    last = (None, {}, {})
    while time.monotonic() < deadline:
        last = _request(method, url, auth=auth, body=body)
        if last[0] == want:
            return last
        time.sleep(2.0)
    return last


def _error_type(payload) -> str:
    error = payload.get("error") if isinstance(payload, dict) else None
    return str(error.get("type") or "") if isinstance(error, dict) else ""


def _markers(result):
    return [h.get("_source", {}).get("marker") for h in result.get("hits", {}).get("hits", [])]


def _code_and_message(exc: ClientError) -> tuple[str, str]:
    error = exc.response.get("Error", {})
    return error.get("Code", "<no code>"), error.get("Message", "<no message>")


def _error_code_and_message(fn) -> tuple[str, str]:
    """The AWS (code, message) `fn` raised; an unexpected success raises instead of returning one."""
    try:
        fn()
    except ClientError as exc:
        return _code_and_message(exc)
    raise AssertionError("the call succeeded, but an error was expected")


def _wait_stack_create(cfn, stack_id, max_attempts, ctx=None) -> None:
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts})
    except Exception as err:  # noqa: BLE001 -- surface the resource-level reason
        if ctx is not None and _budget_spent(ctx):
            raise TimeoutError(f"stack {stack_id} to create: the run budget ended first; not graded") from err
        events = cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
        reasons = [f"{e['LogicalResourceId']}: {e.get('ResourceStatus')}: "
                   f"{e.get('ResourceStatusReason')}"
                   for e in events if str(e.get("ResourceStatus", "")).endswith("FAILED")]
        raise AssertionError(f"stack {stack_id} did not reach CREATE_COMPLETE: {reasons!r}") from err


def _wait_domain_ready(osc, domain_name, timeout_s: float = 900.0, ctx=None) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Created") and last.get("Processing") is False and last.get("Endpoint"):
            return last
        time.sleep(2.0)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} to become ready: the run budget ended first; not graded")
    raise AssertionError(
        f"domain {domain_name} not ready within {timeout_s}s (Processing="
        f"{last.get('Processing')!r}, Endpoint={last.get('Endpoint')!r})")


def _wait_domain_gone(osc, domain_name, timeout_s: float, ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            code, message = _code_and_message(exc)
            expected = ("ResourceNotFoundException", f"Domain not found: {domain_name}")
            assert (code, message) == expected, (
                f"DescribeDomain after delete: {code!r}: {message!r}, expected {expected!r}"
            )
            return
        time.sleep(2.0)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} to disappear: the run budget ended first; not graded")
    raise AssertionError(
        f"domain {domain_name} still described {timeout_s}s after DELETE_COMPLETE: "
        f"Deleted={last.get('Deleted')!r} Processing={last.get('Processing')!r}")


def _delete_stack_and_wait(cfn, stack_name) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900})
    except Exception as exc:  # noqa: BLE001 -- on_cleanup swallows; say so on stderr
        import sys
        raise RuntimeError(f"stack {stack_name} delete did not complete: {exc}") from exc


def _delete_domain_quietly(osc, domain_name) -> None:
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _force_delete_secret(sm, secret_name) -> None:
    sm.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
