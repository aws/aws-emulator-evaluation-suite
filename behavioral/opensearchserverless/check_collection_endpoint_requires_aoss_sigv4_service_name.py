"""collection-endpoint-requires-aoss-sigv4-service-name."""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import ReadOnlyCredentials
from botocore.exceptions import ClientError

CHECK = "collection-endpoint-requires-aoss-sigv4-service-name"
GROUP = "data-plane"
SERVICES = ["opensearchserverless"]

# AWS behaviors this check relies on:
#
#   IAM permission. A data access policy is NOT sufficient to reach an aoss collection's data plane
#   (developerguide/serverless-data-access.html, "Data access policies versus IAM policies"): the
#   signing principal must ALSO hold the IAM permission `aoss:APIAccessAll` for the collection, or
#   every data-plane call is refused. The check signs with an assumed session of a throwaway role
#   holding exactly that permission, scoped to this collection. `aoss:DashboardsAccessAll` only
#   gates browser access to Dashboards and is not granted.
#
#   `x-amz-content-sha256`. Every signed request that carries a body must send the payload's sha256
#   hex digest in this header; without it aoss refuses the request with its generic front-door 403
#   (`{"status":403,"error":{"type":"Forbidden","reason":"403 Forbidden"}}`).
#
#   Refusal shape. The front-door 403 for a wrong SigV4 scope carries no explanatory message; its
#   `error.type == "forbidden"` is what tells it apart from OpenSearch's own access control, which
#   always names itself `security_exception`. The "es"-scope leg asserts that discriminator.
#
#   GET-by-id is not realtime on aoss: a `GET <index>/_doc/<id>` right after its own `201 created`
#   write can return `found: false`, so every read of a fresh write is a bounded poll
#   (`_poll_found`); a read proving ABSENCE after a REFUSED write stays a single read.

# ===== helpers =====

# A dp:endpoint FAIL marker: a detail containing it reports a published collectionEndpoint with no
# listener behind it as a failed check rather than as a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
# The control-plane counterpart, for a collection the target accepted and never converged.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"

_ACTIVE_BUDGET_S = 300.0
_POLICY_PROPAGATION_BUDGET_S = 240.0
_READ_AFTER_WRITE_BUDGET_S = 60.0
_REQUEST_TIMEOUT_S = 25
_DELETE_BUDGET_S = 180.0
_ASSUME_BUDGET_S = 90.0
#: Codes AssumeRole answers with while a freshly created role's trust policy propagates.
_ASSUME_TRANSIENT_CODES = ("AccessDenied", "MalformedPolicyDocument", "InvalidClientTokenId")


def _aoss_name(ctx, prefix: str, maxlen: int = 32) -> str:
    """A name matching aoss's ``^[a-z][a-z0-9-]+$`` within ``maxlen`` (policy 32, collection 64)."""
    raw = ctx.unique_name(prefix).lower()
    kept = "".join(ch if (ch.isalpha() and ch.isascii()) or ch.isdigit() or ch == "-" else "-"
                   for ch in raw)
    while "--" in kept:
        kept = kept.replace("--", "-")
    kept = kept.strip("-")
    if not kept or not kept[0].isalpha():
        kept = "a" + kept
    return kept[:maxlen].rstrip("-")


def _error(fn):
    """``(code, message)`` for a refused call. RAISES on unexpected success: a falsy
    sentinel would let an over-permissive target pass acceptance off as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected this call to be refused, but it succeeded with {result!r}")


def _create_role(ctx) -> tuple[str, str]:
    """Create-or-adopt a throwaway IAM role this run's own principal can assume -> ``(arn, name)``.

    Trust-only at this point: the ``aoss:APIAccessAll`` grant is attached separately by
    ``_grant_data_plane_access`` once the collection id it must be scoped to exists. Tagged and
    torn down like every other resource this check creates.
    """
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_name = _aoss_name(ctx, "sim2real-aoss-dp-", maxlen=64)
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "sts:AssumeRole",
        }],
    })
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"], role_name


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for call in (
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="aoss-api-access"),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchEntity", "NoSuchEntityException"):
                raise


def _grant_data_plane_access(ctx, role_name: str, region: str, account: str, coll_id: str) -> None:
    """Attach the ONE IAM identity permission real AWS requires before any signed request reaches
    an aoss collection's data plane: ``aoss:APIAccessAll``, scoped to this collection.

    Confirmed against AWS's own docs (developerguide/serverless-data-access.html): a data access
    policy is NOT sufficient on its own -- "If a principal doesn't have [this] IAM permission, they
    will receive 403 errors when attempting to send requests to the collection." A data access
    policy and this IAM permission propagate independently, so `_wait_index_creatable`'s retry
    covers both, not just the data access policy.
    """
    ctx.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName="aoss-api-access",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "aoss:APIAccessAll",
                "Resource": f"arn:aws:aoss:{region}:{account}:collection/{coll_id}",
            }],
        }),
    )


def _assume(ctx, role_arn: str) -> ReadOnlyCredentials:
    """AssumeRole with a bounded retry over the trust policy's own propagation, never a sleep."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + _ASSUME_BUDGET_S
    last_code = ""
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-aoss-scope",
            )["Credentials"]
            return ReadOnlyCredentials(
                creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"],
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in _ASSUME_TRANSIENT_CODES:
                raise
            last_code = code
        time.sleep(5.0)
    raise AssertionError(
        f"AssumeRole on {role_arn} did not succeed within {_ASSUME_BUDGET_S:.0f}s "
        f"(last error {last_code!r}); the trust policy never propagated"
    )


def _signed(ctx, frozen, method, url, *, body=None, service="aoss"):
    """SigV4-signed HTTPS request to the collection endpoint -> ``(status, parsed_json)``.

    ``frozen`` is the assumed-role session's own credentials, never the harness's ambient identity:
    the harness role is not what the data access policy or the IAM grant name. ``service`` is the
    SIGNING SCOPE NAME and is the subject of this check: aoss collections are signed ``aoss``, not
    ``es``. Requests that carry a body also send an explicit ``x-amz-content-sha256`` header.
    Without it, real aoss refuses every body-bearing signed request with the SAME generic
    front-door 403 a genuine SigV4 scope mismatch produces, which would make a missing header
    indistinguishable from the very thing this check exists to test.
    """
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    if data is not None:
        headers["x-amz-content-sha256"] = hashlib.sha256(data).hexdigest()
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, service, ctx.region).add_auth(aws_req)
    target, route = ctx.endpoint_route(url)
    req = urllib.request.Request(target, data=data, method=method, headers={**dict(aws_req.headers), **route})
    try:
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT_S) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}
    except urllib.error.URLError as exc:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: the target published a collection endpoint at {url} but nothing "
            f"answered a signed {method} there ({exc}); a collection endpoint that does not serve "
            "is a data-plane gap, not an environment error"
        ) from exc


def _create_collection(ctx, coll_name: str) -> str:
    """Create-or-adopt a SEARCH collection with an inline AWS-owned key, tagged for cleanup."""
    osc = ctx.client("opensearchserverless")
    # Teardown registered BEFORE the create so a failure in between cannot leak billable OCUs.
    holder: dict[str, str] = {}
    ctx.on_cleanup(lambda: _delete_collection_when_stable(ctx, holder.get("id")))
    try:
        detail = osc.create_collection(
            name=coll_name,
            type="SEARCH",
            encryptionConfig={"aWSOwnedKey": True},
            tags=[{"key": "sim2real", "value": CHECK}],
        )["createCollectionDetail"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConflictException":
            raise
        found = osc.batch_get_collection(names=[coll_name])["collectionDetails"]
        assert found, (
            f"CreateCollection reported ConflictException for {coll_name!r} but "
            "BatchGetCollection returns no collection under that name"
        )
        detail = found[0]
    holder["id"] = detail["id"]
    return detail["id"]


def _delete_collection_when_stable(ctx, coll_id, timeout_s: float = _DELETE_BUDGET_S) -> None:
    """Teardown. DeleteCollection is refused while a collection is CREATING, so retry until it is
    accepted or the collection is already gone. RAISES on exhaustion, so a leak is reported instead
    of hidden: a cut-off teardown otherwise PASSES while billable OCUs stay up.
    """
    if not coll_id:
        return
    osc = ctx.client("opensearchserverless")
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        try:
            osc.delete_collection(id=coll_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException":
                raise
            last = code
        time.sleep(5.0)
    raise AssertionError(
        f"collection {coll_id} could not be deleted within {timeout_s}s (last error {last!r}); "
        "it is LEAKED and still billing OCUs"
    )


def _wait_collection_active(ctx, coll_id: str, timeout_s: float = _ACTIVE_BUDGET_S) -> dict:
    """Bounded poll to ACTIVE. Raises on FAILED and on exhaustion; the terminal set deliberately
    excludes FAILED so a failed collection can never satisfy the wait.
    """
    osc = ctx.client("opensearchserverless")
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        details = osc.batch_get_collection(ids=[coll_id])["collectionDetails"]
        if details:
            last = details[0]
            status = last["status"]
            if status == "ACTIVE":
                return last
            if status in ("FAILED", "UPDATE_FAILED"):
                raise AssertionError(
                    f"collection {coll_id} entered {status}: {last.get('failureMessage')!r}"
                )
        time.sleep(5.0)
    raise AssertionError(
        f"{STATE_MARKER}: collection {coll_id} never reached ACTIVE within {timeout_s}s "
        f"(last status {last.get('status')!r}); the target accepted CreateCollection and never "
        "converged"
    )


def _create_policies(ctx, coll_name: str, role_arn: str) -> None:
    """Network policy (public) + data access policy (the throwaway role, full index rights). Both
    are prerequisites for ANY signed request to reach the collection endpoint -- alongside the IAM
    ``aoss:APIAccessAll`` grant attached separately in ``_grant_data_plane_access`` -- and all are
    created in-check so this works against a target that has nothing. The Principal is the ROLE arn:
    a data access policy's Principal element only ever accepts IAM role/user ARNs or SAML identities
    (developerguide/serverless-data-access.html), never an STS session ARN, and signing through an
    assumed session of a role created for exactly this purpose sidesteps that distinction entirely.
    """
    osc = ctx.client("opensearchserverless")
    net_name = _aoss_name(ctx, "sim2real-aoss-net-")
    osc.create_security_policy(
        type="network",
        name=net_name,
        policy=json.dumps([
            {
                "Rules": [
                    {"ResourceType": "collection", "Resource": [f"collection/{coll_name}"]},
                ],
                "AllowFromPublic": True,
            }
        ]),
    )
    ctx.on_cleanup(lambda: _delete_policy(ctx, "security", "network", net_name))

    dap_name = _aoss_name(ctx, "sim2real-aoss-dap-")
    osc.create_access_policy(
        type="data",
        name=dap_name,
        policy=json.dumps([
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": [f"collection/{coll_name}"],
                        "Permission": [
                            "aoss:CreateCollectionItems",
                            "aoss:DescribeCollectionItems",
                        ],
                    },
                    {
                        "ResourceType": "index",
                        "Resource": [f"index/{coll_name}/*"],
                        "Permission": [
                            "aoss:CreateIndex",
                            "aoss:DescribeIndex",
                            "aoss:ReadDocument",
                            "aoss:WriteDocument",
                            "aoss:DeleteIndex",
                        ],
                    },
                ],
                "Principal": [role_arn],
            }
        ]),
    )
    ctx.on_cleanup(lambda: _delete_policy(ctx, "access", "data", dap_name))


def _delete_policy(ctx, kind: str, policy_type: str, name: str) -> None:
    osc = ctx.client("opensearchserverless")
    fn = osc.delete_security_policy if kind == "security" else osc.delete_access_policy
    try:
        fn(type=policy_type, name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_index_creatable(ctx, frozen, base: str, index: str) -> float:
    """Create the index, retrying while the data access policy AND the IAM ``aoss:APIAccessAll``
    grant propagate, and RETURN the measured latency so a later window can be calibrated on it
    rather than on a guessed constant.

    AWS documents the data-access-policy lag explicitly ("wait approximately 30 to 60 seconds for
    the policy to propagate ... If you receive a 403 Forbidden error, wait and retry"), and the IAM
    grant propagates on IAM's own independent eventual-consistency window, so a 403 here is a
    prerequisite still settling, not the refusal this check is about -- that one is asserted below
    against an ALREADY-authorised endpoint.
    """
    deadline = time.monotonic() + _POLICY_PROPAGATION_BUDGET_S
    started = time.monotonic()
    last: tuple = ()
    while time.monotonic() < deadline:
        status, body = _signed(
            ctx, frozen, "PUT", f"{base}/{index}",
            body={"mappings": {"properties": {"field": {"type": "keyword"}}}},
        )
        if status in (200, 201):
            return time.monotonic() - started
        if status == 400 and "resource_already_exists" in json.dumps(body):
            return time.monotonic() - started
        last = (status, body)
        time.sleep(5.0)
    raise AssertionError(
        f"{DATAPLANE_MARKER}: the collection endpoint never authorised PUT /{index} within "
        f"{_POLICY_PROPAGATION_BUDGET_S}s despite a matching data access policy AND a matching "
        f"aoss:APIAccessAll IAM grant (last {last!r})"
    )


def _poll_found(ctx, frozen, url: str, timeout_s: float = _READ_AFTER_WRITE_BUDGET_S) -> dict:
    """Bounded poll of GET *url* until it reports ``found: true``, never a single immediate read.

    A GET by id issued immediately after its own 201-created write can return ``found: false``:
    GET-by-id on aoss is NOT realtime the way it is on managed OpenSearch, so a bare post-write
    read is a flake, not a bug, on a correct target. RAISES on timeout rather than returning the
    last (not-found) observation.
    """
    deadline = time.monotonic() + timeout_s
    last: tuple = ()
    while time.monotonic() < deadline:
        status, body = _signed(ctx, frozen, "GET", url)
        if status == 200 and body.get("found") is True:
            return body
        last = (status, body)
        time.sleep(2.0)
    raise AssertionError(
        f"{DATAPLANE_MARKER}: GET {url} never reported found=true within {timeout_s:.0f}s after "
        f"its own write was accepted (last {last!r})"
    )


# ===== end helpers =====


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A collection's OpenSearch HTTP endpoint validates SigV4 against the signing service name
    ``aoss``: the byte-identical request signed with ``es`` is refused and its document never lands,
    and re-signing it with ``aoss`` (as a role holding ``aoss:APIAccessAll``) makes it succeed.
    """
    osc = ctx.client("opensearchserverless")
    account = ctx.client("sts").get_caller_identity()["Account"]
    coll_name = _aoss_name(ctx, "sim2real-aoss-scope-", maxlen=64)

    role_arn, role_name = _create_role(ctx)
    _create_policies(ctx, coll_name, role_arn)
    coll_id = _create_collection(ctx, coll_name)
    _grant_data_plane_access(ctx, role_name, ctx.region, account, coll_id)
    frozen = _assume(ctx, role_arn)
    active = _wait_collection_active(ctx, coll_id)

    endpoint = active.get("collectionEndpoint")
    assert not (p := ctx.published_url_mismatch(endpoint, labels=("aoss",))), p
    base = endpoint.rstrip("/")
    index = "sim2real-scope"

    propagation_s = _wait_index_creatable(ctx, frozen, base, index)

    # --- POSITIVE CONTROL: aoss-signed write, then an independent read via a DIFFERENT HTTP
    # operation. Without this leg, "es is refused" is indistinguishable from "everything is
    # refused". The read is a bounded poll, not a single GET: GET-by-id
    # is not immediately consistent with a preceding write on aoss (see ``_poll_found``).
    status, body = _signed(
        ctx, frozen, "PUT", f"{base}/{index}/_doc/allowed", body={"field": "signed-with-aoss"},
    )
    assert status in (200, 201), (
        f"expected an aoss-signed PUT /{index}/_doc/allowed to be accepted with 200 or 201, got "
        f"HTTP {status}: {body!r}"
    )
    got = _poll_found(ctx, frozen, f"{base}/{index}/_doc/allowed")
    assert got.get("_source", {}).get("field") == "signed-with-aoss", (
        f"expected the stored _source.field to be 'signed-with-aoss' exactly, got "
        f"{got.get('_source')!r}"
    )

    # --- BREAK EXACTLY ONE THING: the signing scope. Same method, same URL, same body, same
    # credentials, same clock -- only the service name in the credential scope changes.
    status, refused = _signed(
        ctx, frozen, "PUT", f"{base}/{index}/_doc/scoped-es", body={"field": "signed-with-es"},
        service="es",
    )
    assert status == 403, (
        f"expected HTTP 403 for a request signed with scope 'es' against an aoss collection "
        f"endpoint, got HTTP {status}: {refused!r} -- an aoss endpoint that accepts the managed "
        "OpenSearch signing scope is not validating the credential scope at all"
    )
    refused_type = str((refused.get("error") or {}).get("type", "")).lower()
    assert refused_type == "forbidden", (
        f"expected the 403 body's error.type to be aoss's generic front-door rejection "
        f"('forbidden' -- the SigV4 credential-scope check, which this request is ALREADY known to "
        f"pass every other prerequisite for: same identity, same data access policy, same "
        f"x-amz-content-sha256 discipline as the accepted aoss-signed write above), not "
        f"OpenSearch's own permission-layer 'security_exception', got {refused.get('error')!r} for "
        f"body {refused!r}"
    )

    # --- EFFECT ABSENT, via an independent read at the destination.
    status, missing = _signed(ctx, frozen, "GET", f"{base}/{index}/_doc/scoped-es")
    assert status == 404, (
        f"expected HTTP 404 reading /{index}/_doc/scoped-es after the es-signed write was refused, "
        f"got HTTP {status}: {missing!r} -- the refused write landed anyway"
    )
    assert missing.get("found") is False, (
        f"expected found=False for the document whose write was refused, got {missing!r}"
    )

    # --- RESTORE: re-sign the identical request with aoss. It must now succeed, proving the earlier
    # refusal was about the scope and not about this document, index, or moment.
    status, body = _signed(
        ctx, frozen, "PUT", f"{base}/{index}/_doc/scoped-es", body={"field": "signed-with-es"},
    )
    assert status in (200, 201), (
        f"expected the identical request re-signed with scope 'aoss' to be accepted with 200 or "
        f"201, got HTTP {status}: {body!r} (data access policy propagated in "
        f"{propagation_s:.1f}s, so this is not a propagation artefact)"
    )
    restored = _poll_found(ctx, frozen, f"{base}/{index}/_doc/scoped-es")
    assert restored.get("_source", {}).get("field") == "signed-with-es", (
        f"expected the restored _source.field to be 'signed-with-es' exactly, got "
        f"{restored.get('_source')!r}"
    )

    # The control plane must still agree the collection is the one we asserted against.
    final = osc.batch_get_collection(ids=[coll_id])["collectionDetails"][0]
    assert final["collectionEndpoint"].rstrip("/") == base, (
        f"expected BatchGetCollection to keep reporting collectionEndpoint {base!r}, got "
        f"{final.get('collectionEndpoint')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
