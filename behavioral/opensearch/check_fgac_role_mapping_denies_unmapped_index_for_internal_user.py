"""fgac-role-mapping-denies-unmapped-index-for-internal-user."""
from __future__ import annotations

import base64
import http.client
import json
import random
import secrets
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "fgac-role-mapping-denies-unmapped-index-for-internal-user"
GROUP = 'overly-permissive'
SERVICES = ['opensearch']

# ===== shared domain helpers =====

ENGINE_VERSION = "OpenSearch_2.11"
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Prefix of the failure raised when a domain endpoint the target published does not answer, so
# that outcome reads as the target's failure rather than as a local network problem.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
# The CONTROL-PLANE convergence counterpart, for a domain that was accepted and never converged.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"

_SCENARIO = "fgac-role-mapping-denies-unmapped-index"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state, the same on every target.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created / already deleted.

    Anything other than "already gone" is re-raised: ``ctx.on_cleanup`` swallows exceptions, so a
    silently-failed delete leaks a 24x7 cluster while the check still passes.
    """
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _basic_request(method, url, user, password, *, body=None):
    """HTTP-basic-authenticated request to a fine-grained-access-control domain endpoint.

    FGAC authenticates the internal user database over basic auth, NOT SigV4 -- which is the whole
    point of this check: the identity under test is an OpenSearch user, not an IAM principal.
    """
    data = json.dumps(body).encode() if body is not None else None
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {token}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}
    except (OSError, http.client.HTTPException) as exc:  # the endpoint did not answer at all
        # An HTTP status (above) is data the caller asserts on; a transport failure is not, and
        # urllib reports it in wording that reads as a local network problem ("Connection refused",
        # "timed out"), which leaves the pass+fail denominator. The endpoint here was published by
        # the target itself, so failing to answer on it is the target's fidelity failure.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: basic-auth {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _create_fgac_domain(ctx, admin_user: str, admin_password: str) -> str:
    """Create the cheapest legal FGAC domain, cleanup registered BEFORE the create call.

    Fine-grained access control has three co-requirements -- encryption at rest, node-to-node
    encryption and EnforceHTTPS -- and CreateDomain refuses the request without all three.
    """
    osc = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    # Registered BEFORE the create so a failure between create and registration can never leak a
    # 24x7 cluster.
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1,
                       "DedicatedMasterEnabled": False, "ZoneAwarenessEnabled": False},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        EncryptionAtRestOptions={"Enabled": True},
        NodeToNodeEncryptionOptions={"Enabled": True},
        DomainEndpointOptions={"EnforceHTTPS": True,
                               "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"},
        AdvancedSecurityOptions={
            "Enabled": True,
            "InternalUserDatabaseEnabled": True,
            "MasterUserOptions": {"MasterUserName": admin_user,
                                  "MasterUserPassword": admin_password},
        },
        # With FGAC on, the security plugin is the authorizer, so the resource policy is open and
        # every refusal this check observes comes from the role mapping rather than from IAM.
        AccessPolicies=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": "*"},
                           "Action": "es:*",
                           "Resource": f"arn:aws:es:{ctx.region}:{account_id}:"
                                       f"domain/{domain_name}/*"}]}),
        # Tagged at creation so tag-based cleanup can find it if this check's own cleanup never runs.
        TagList=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    # CreateDomain is aggressively rate limited per account: jitter before the first attempt, then
    # back off on throttling for every attempt after.
    for attempt in range(12):
        time.sleep(random.uniform(0, 20.0) if attempt == 0 else 6.0 * attempt + random.uniform(0, 6.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1200.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep."""
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        try:
            last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            # Concurrent domain polls in one account hit DescribeDomain's rate limit: poll again.
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(2)
            continue
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2)
    raise _never_ready(
        f"FGAC domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})")


def _wait_admin_auth(ctx, base: str, user: str, password: str,
                      timeout_s: float = 300.0) -> None:
    """Processing=False does not mean the security plugin has loaded its config yet.

    Polls the admin user's own cluster-health call, which is the observable condition -- and it is
    also the BARRIER for everything after it: the refusal this check grades is only meaningful once
    an authorized call is known to work, or a still-initialising plugin's 403 is indistinguishable
    from a real denial.
    """
    deadline = time.monotonic() + timeout_s
    status, body = None, {}
    while time.monotonic() < deadline:
        status, body = _basic_request("GET", f"{base}/_cluster/health", user, password)
        if status == 200:
            return
        time.sleep(2)
    raise _never_ready(
        f"the admin user's basic-auth call did not succeed within {timeout_s}s "
        f"(last HTTP {status!r}: {body!r})")


def _wait_security_config_effective(ctx, base: str, url: str, user: str, password: str,
                                    timeout_s: float = 240.0) -> tuple:
    """Wait until a just-created role mapping has taken effect, on the POSITIVE path.

    Security-config changes propagate to the plugin's index asynchronously and a not-yet-effective
    mapping answers 403 -- the SAME status as the denial under test. So the barrier is a
    SUCCESSFUL authorized call, never the refusal itself: poll until the mapped user can read its
    OWN index, and only then probe the index it must not read.
    """
    deadline = time.monotonic() + timeout_s
    status, body = None, {}
    while time.monotonic() < deadline:
        status, body = _basic_request("POST", url, user, password,
                                      body={"query": {"match_all": {}}})
        if status == 200:
            return status, body
        time.sleep(2)
    raise _never_ready(
        f"the mapped user's own index never became readable within {timeout_s}s, so a 403 on the "
        f"unmapped index could not be attributed to authorisation (last HTTP {status!r}: {body!r})")


def _error_type(payload) -> str:
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}.

    Structural, single-valued and never an alternation: the security plugin puts the type in
    ``error.type`` (and repeats it under ``error.root_cause[0].type``), so a caller reads one field
    rather than accepting either.
    """
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return ""


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


# ===== end shared domain helpers =====


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An internal user mapped to a read role on one index can search it over basic auth and is refused
    HTTP 403 security_exception on a second index the admin user can still read, without the
    denied document leaking.
    """
    admin_user = "sim2realadmin"
    # Generated at run time and never logged: no assert message below interpolates a password.
    admin_password = "Aa1!" + secrets.token_urlsafe(18)
    limited_user = "sim2reallimited"
    limited_password = "Bb2!" + secrets.token_urlsafe(18)

    domain = _create_fgac_domain(ctx, admin_user, admin_password)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_admin_auth(ctx, base, admin_user, admin_password)

    allowed, denied = "sim2real-behav-allowed", "sim2real-behav-denied"
    for index, marker in ((allowed, "allowed-doc"), (denied, "denied-doc")):
        status, created = _basic_request("PUT", f"{base}/{index}", admin_user, admin_password,
                                         body={"settings": {"index": {
                                             "number_of_shards": 1, "number_of_replicas": 0}}})
        assert status == 200, f"creating {index!r} returned HTTP {status!r}: {created!r}"
        status, indexed = _basic_request("PUT", f"{base}/{index}/_doc/1", admin_user,
                                         admin_password, body={"marker": marker})
        assert status == 201, f"indexing into {index!r} returned HTTP {status!r}: {indexed!r}"
        status, _ = _basic_request("POST", f"{base}/{index}/_refresh", admin_user, admin_password)
        assert status == 200, f"_refresh of {index!r} returned HTTP {status!r}"

    role = "sim2real_limited_role"
    status, role_body = _basic_request(
        "PUT", f"{base}/_plugins/_security/api/roles/{role}", admin_user, admin_password,
        body={"cluster_permissions": ["cluster_composite_ops_ro"],
              "index_permissions": [{"index_patterns": [allowed],
                                     "allowed_actions": ["read", "search"]}]})
    ctx.on_cleanup(lambda: _basic_request(
        "DELETE", f"{base}/_plugins/_security/api/roles/{role}", admin_user, admin_password))
    assert status in (200, 201), f"creating role {role!r} returned HTTP {status!r}: {role_body!r}"

    status, user_body = _basic_request(
        "PUT", f"{base}/_plugins/_security/api/internalusers/{limited_user}",
        admin_user, admin_password, body={"password": limited_password})
    ctx.on_cleanup(lambda: _basic_request(
        "DELETE", f"{base}/_plugins/_security/api/internalusers/{limited_user}",
        admin_user, admin_password))
    assert status in (200, 201), (
        f"creating internal user {limited_user!r} returned HTTP {status!r}: {user_body!r}"
    )

    status, map_body = _basic_request(
        "PUT", f"{base}/_plugins/_security/api/rolesmapping/{role}",
        admin_user, admin_password, body={"users": [limited_user]})
    ctx.on_cleanup(lambda: _basic_request(
        "DELETE", f"{base}/_plugins/_security/api/rolesmapping/{role}",
        admin_user, admin_password))
    assert status in (200, 201), (
        f"mapping {limited_user!r} onto {role!r} returned HTTP {status!r}: {map_body!r}"
    )

    # Positive control AND propagation barrier: the mapped user reads its own index.
    allowed_status, allowed_body = _wait_security_config_effective(
        ctx, base, f"{base}/{allowed}/_search", limited_user, limited_password)
    assert allowed_status == 200, (
        f"the positive control failed: the mapped user got HTTP {allowed_status!r} on its own "
        f"index: {allowed_body!r}"
    )
    assert _total(allowed_body) == 1, (
        f"the mapped user's search of its own index returned {_total(allowed_body)!r} hits, "
        f"expected 1: {allowed_body!r}"
    )
    markers = [h.get("_source", {}).get("marker") for h in allowed_body["hits"]["hits"]]
    assert markers == ["allowed-doc"], (
        f"the mapped user read {markers!r} from its own index, expected ['allowed-doc']"
    )

    # The one thing that differs: an index the role mapping does not name.
    denied_status, denied_body = _basic_request(
        "POST", f"{base}/{denied}/_search", limited_user, limited_password,
        body={"query": {"match_all": {}}})
    assert denied_status == 403, (
        f"the unmapped index returned HTTP {denied_status!r} to the limited user, expected 403: "
        f"{denied_body!r}"
    )
    assert _error_type(denied_body) == "security_exception", (
        f"expected security_exception, got {_error_type(denied_body)!r}: {denied_body!r}"
    )
    assert "no permissions for" in str(denied_body).lower(), (
        f"the 403 body does not name the missing permission: {denied_body!r} -- a refusal that "
        f"does not say what was missing is indistinguishable from an authentication failure"
    )
    assert "indices:data/read/search" in str(denied_body), (
        f"the 403 body does not name the action that was refused: {denied_body!r}"
    )
    # Effect absent, twice: the refusal leaks no content, and the document is still there.
    assert "denied-doc" not in str(denied_body), (
        f"the refusal leaked the denied document's content: {denied_body!r}"
    )
    admin_status, admin_body = _basic_request(
        "POST", f"{base}/{denied}/_search", admin_user, admin_password,
        body={"query": {"match_all": {}}})
    assert admin_status == 200, (
        f"the admin user got HTTP {admin_status!r} on the denied index, so the 403 above cannot "
        f"be attributed to authorisation: {admin_body!r}"
    )
    admin_markers = [h.get("_source", {}).get("marker") for h in admin_body["hits"]["hits"]]
    assert admin_markers == ["denied-doc"], (
        f"the admin user reads {admin_markers!r} from the denied index, expected "
        f"['denied-doc'] -- the refusal must be authorisation, not absence"
    )

    # And the limited user is still refused after the admin's successful read, so the 403 is not
    # a transient that resolved.
    again_status, again_body = _basic_request(
        "GET", f"{base}/{denied}/_doc/1", limited_user, limited_password)
    assert again_status == 403, (
        f"a direct GET of the denied document returned HTTP {again_status!r} to the limited user, "
        f"expected 403 -- a refusal that only applies to _search is not an index-level grant: "
        f"{again_body!r}"
    )

    for index in (allowed, denied):
        _basic_request("DELETE", f"{base}/{index}", admin_user, admin_password)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
