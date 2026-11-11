"""xsvc-cloudfront-2-lambda-edge-unpublished-version-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudfront-2-lambda-edge-unpublished-version-rejected"
GROUP = "lambda-edge-association"
SERVICES = ["cloudfront", "lambda"]

#: Lambda@Edge functions MUST live in us-east-1, and CloudFront's control plane is global and signed
#: there. A genuinely region-pinned resource, so this literal is the contract, not account state.
EDGE_REGION = "us-east-1"

#: Marker a FAIL detail carries when the target's endpoint data plane is unimplemented.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Managed CachingDisabled: every viewer request reaches the viewer-request trigger regardless.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

#: The header the edge function sets on the response it generates.
EDGE_HEADER = "x-sim2real-edge"

#: Lambda@Edge forbids environment variables, so the run's marker is baked into the source. The
#: function GENERATES the viewer response, so the origin is never contacted and the marker in the
#: body and header can only have come from this run's code executing at the edge.
_FUNCTION_TEMPLATE = '''\
MARKER = {marker!r}


def handler(event, context):
    request = event["Records"][0]["cf"]["request"]
    return {{
        "status": "200",
        "statusDescription": "OK",
        "headers": {{
            "{header}": [{{"key": "{header}", "value": MARKER}}],
            "content-type": [{{"key": "Content-Type", "value": "text/plain"}}],
        }},
        "body": MARKER + " " + request["uri"],
    }}
'''

_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}

_EDGE_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": ["lambda.amazonaws.com", "edgelambda.amazonaws.com"]},
        "Action": "sts:AssumeRole",
    }],
}

_TAGS = [{"Key": "sim2real", "Value": "xsvc-cloudfront-2"}]


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _error_of(fn):
    """Return (http_status, error_code, message) of the ClientError ``fn`` raises.

    Raises AssertionError if ``fn`` SUCCEEDS — an accepted call is the strongest possible signal and
    must never be confused with an error-code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response["ResponseMetadata"]["HTTPStatusCode"],
                exc.response.get("Error", {}).get("Code"),
                exc.response.get("Error", {}).get("Message"))
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=1200.0, interval_s=10.0) -> str:
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment."""
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _teardown_distribution(cf, dist_id, timeout_s=1500.0) -> None:
    """Disable, wait for Deployed, delete -- called from the check body on the success path,
    since disable -> Deployed takes minutes."""
    resp = cf.get_distribution_config(Id=dist_id)
    cfg = resp["DistributionConfig"]
    if cfg["Enabled"]:
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=cfg)
    cf.delete_distribution(Id=dist_id, IfMatch=_wait_distribution_deployed(cf, dist_id,
                                                                            timeout_s=timeout_s))


def _disable_distribution(cf, dist_id) -> None:
    """Failure-path net: disable the distribution and return WITHOUT waiting for the change to
    deploy. The success path deletes it in the body (_teardown_distribution), so here it is
    normally gone. The cleanup chain is bounded at 60 s and disable -> Deployed -> delete takes
    minutes; disabling takes seconds, so the function and IAM role behind it are still reached
    inside the bound.
    """
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        cfg = cfg_resp["DistributionConfig"]
        if cfg.get("Enabled"):
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
        raise RuntimeError(f"cloudfront distribution {dist_id} disabled, not deleted (deploy wait exceeds "
                           f"the cleanup bound); its sim2real comment makes it reap_leftovers.py's to delete")
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchDistribution",):
            raise RuntimeError(f"cloudfront distribution {dist_id}: {exc!r}") from exc


def _delete_edge_function(lam, name) -> None:
    """One DeleteFunction attempt; a refusal raises naming the function. A replicated function is
    refused (InvalidParameterValueException) until CloudFront removes its edge replicas after the
    distribution is deleted, so a retry would only eat the cleanup bound the IAM role needs.
    Note: the body deletes the distribution, but replica removal can lag it by hours, so this
    refusal can still be reported after a passing run; the function is then reaped later.
    """
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != "ResourceNotFoundException":
            raise RuntimeError(f"lambda@edge function {name} in {EDGE_REGION} not deleted: {code}: "
                               f"{exc.response.get('Error', {}).get('Message')}") from exc


def _zip_source(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("index.py", source)
    return buf.getvalue()


def _distributions_with_comment(cf, comment) -> list:
    """Every distribution carrying ``comment``, across all pages — the query, not the account,
    decides emptiness, because the comment is minted by this run."""
    found, marker = [], None
    while True:
        kwargs = {"MaxItems": "100"}
        if marker:
            kwargs["Marker"] = marker
        page = cf.list_distributions(**kwargs)["DistributionList"]
        found += [d["Id"] for d in page.get("Items", []) if d.get("Comment") == comment]
        if not page.get("IsTruncated"):
            return found
        marker = page["NextMarker"]


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:control",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A Lambda@Edge association must name a published version whose role trusts edgelambda: $LATEST
    and a lambda-only role are each refused with no distribution left; once the trust is fixed the
    version is accepted and the function generates the edge response carrying this run's marker.
    """
    cf = ctx.client("cloudfront", region=EDGE_REGION)
    lam = ctx.client("lambda", region=EDGE_REGION)
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    marker = ctx.unique_name("sim2real-edge-marker-")
    comment = ctx.unique_name("sim2real xsvc-cloudfront-2 lambda-edge ")

    role_name = ctx.unique_name("sim2real-xsvc-edge-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST),
        Description="sim2real lambda@edge association check",
        Tags=_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))
    # Deliberately NO permission policy on the role: without logs:* the edge replicas cannot create
    # /aws/lambda/us-east-1.<fn> log groups in whichever regions serve the request, so this check
    # leaves no log groups behind anywhere.

    function_name = ctx.unique_name("sim2real-xsvc-edge-fn-")

    def create_function():
        try:
            return lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip_source(_FUNCTION_TEMPLATE.format(marker=marker,
                                                                       header=EDGE_HEADER))},
                Timeout=5,
                MemorySize=128,
                Publish=False,
                Tags={t["Key"]: t["Value"] for t in _TAGS},
            )
        except ClientError as exc:
            # A not-yet-propagated execution role is reported as InvalidParameterValueException.
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            return None

    created = _poll_until(create_function, lambda r: r is not None, timeout_s=180.0,
                          interval_s=10.0,
                          description=f"CreateFunction to accept the fresh role {role_name}")
    ctx.on_cleanup(lambda: _delete_edge_function(ctx.client("lambda", region=EDGE_REGION),
                                                 function_name))
    function_arn = created["FunctionArn"]
    assert function_arn.split(":")[3] == EDGE_REGION and function_arn.split(":")[4] == account, (
        f"the function must be in {EDGE_REGION} of the calling account, got {function_arn!r}"
    )
    _poll_until(lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
                lambda s: s == "Active", timeout_s=180.0, interval_s=5.0,
                description=f"function {function_name} to become Active")

    version = lam.publish_version(FunctionName=function_name)["Version"]
    assert version.isdigit(), f"PublishVersion must mint a numbered version, got {version!r}"
    version_arn = f"{function_arn}:{version}"

    def distribution_config(lambda_arn: str, ref: str) -> dict:
        return {
            "CallerReference": ctx.unique_name(f"sim2real-xsvc-edge-{ref}-"),
            "Comment": comment,
            "Enabled": True,
            "Origins": {"Quantity": 1, "Items": [{
                # Never contacted: the viewer-request trigger generates every response.
                "Id": "unused-origin",
                "DomainName": "example.com",
                "CustomOriginConfig": {"HTTPPort": 80, "HTTPSPort": 443,
                                       "OriginProtocolPolicy": "https-only"},
            }]},
            "DefaultCacheBehavior": {
                "TargetOriginId": "unused-origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": MANAGED_CACHING_DISABLED,
                "LambdaFunctionAssociations": {"Quantity": 1, "Items": [{
                    "LambdaFunctionARN": lambda_arn,
                    "EventType": "viewer-request",
                    "IncludeBody": False,
                }]},
            },
        }

    def create_dist(lambda_arn: str, ref: str):
        """CreateDistribution, registering teardown the instant one exists — including on a path
        that real AWS refuses, so a target that wrongly accepts cannot leak."""
        resp = cf.create_distribution(DistributionConfig=distribution_config(lambda_arn, ref))
        dist_id = resp["Distribution"]["Id"]
        ctx.on_cleanup(lambda: _disable_distribution(cf, dist_id))
        return resp["Distribution"]

    # BEAT 1 — $LATEST is not a version.
    latest = _error_of(lambda: create_dist(f"{function_arn}:$LATEST", "latest"))
    want_latest = (
        400,
        "InvalidLambdaFunctionAssociation",
        "The function ARN must reference a specific function version. (The ARN must end with the "
        f"version number.) ARN: {function_arn}:$LATEST",
    )
    assert latest == want_latest, (
        f"a viewer-request association naming {function_arn}:$LATEST must be refused with "
        f"{want_latest!r}, got {latest!r}"
    )

    # BEAT 2 — a real published version, but the role is not assumable by edgelambda.
    no_trust = _error_of(lambda: create_dist(version_arn, "notrust"))
    want_no_trust = (
        400,
        "InvalidLambdaFunctionAssociation",
        "The function execution role must be assumable with edgelambda.amazonaws.com as well as "
        f"lambda.amazonaws.com principals. Update the IAM role and try again. Role: {role_arn}",
    )
    assert no_trust == want_no_trust, (
        f"a published version whose role trusts only lambda.amazonaws.com must be refused with "
        f"{want_no_trust!r}, got {no_trust!r}"
    )

    # BEAT 3 — effect absent: neither refusal left a distribution behind.
    leaked = _distributions_with_comment(cf, comment)
    assert leaked == [], f"a refused CreateDistribution still created distribution(s) {leaked!r}"

    # BEAT 4 — repair exactly the trust policy; the SAME version ARN is now accepted. The retry
    # tolerates only the code beat 2 produced, because the trust change is eventually consistent.
    iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(_EDGE_TRUST))

    def try_create():
        try:
            return create_dist(version_arn, "ok")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidLambdaFunctionAssociation":
                raise
            return None

    dist = _poll_until(try_create, lambda d: d is not None, timeout_s=180.0, interval_s=15.0,
                       description="CreateDistribution to accept the version once edgelambda is trusted")
    stored = cf.get_distribution_config(Id=dist["Id"])["DistributionConfig"]
    assoc = stored["DefaultCacheBehavior"]["LambdaFunctionAssociations"]["Items"]
    assert [(a["LambdaFunctionARN"], a["EventType"]) for a in assoc] == [
        (version_arn, "viewer-request")
    ], f"the stored association must be the version ARN on viewer-request, got {assoc!r}"

    _wait_distribution_deployed(cf, dist["Id"])

    # BEAT 5 — the function actually runs at the edge.
    edge, route_headers = ctx.endpoint_route(dist["DomainName"])
    session = requests.Session()
    session.headers.update(route_headers)
    url = f"{edge}/sim2real/first"

    def probe():
        try:
            return session.get(url, timeout=20)
        except requests.RequestException as exc:  # transport only, during edge propagation
            return exc

    try:
        resp = _poll_until(
            probe,
            lambda r: isinstance(r, requests.Response) and r.headers.get(EDGE_HEADER) == marker,
            timeout_s=300.0, interval_s=10.0,
            description=f"the edge function's {EDGE_HEADER} header at {url}",
        )
    except AssertionError as exc:
        last = probe()
        detail = (f"status={last.status_code} headers={dict(last.headers)!r} body={last.text[:300]!r}"
                  if isinstance(last, requests.Response) else repr(last))
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc} | last probe: {detail}") from exc

    assert resp.status_code == 200, (
        f"the viewer-request function returns status 200; the edge answered {resp.status_code!r}"
    )
    assert resp.text == f"{marker} /sim2real/first", (
        f"the body must be the function's own (marker + request uri), got {resp.text[:300]!r}"
    )
    second = session.get(f"{edge}/other/path", timeout=20)
    assert (second.status_code, second.headers.get(EDGE_HEADER), second.text) == (
        200, marker, f"{marker} /other/path"
    ), (
        f"a second path must also be answered by the function with its uri, got "
        f"{(second.status_code, second.headers.get(EDGE_HEADER), second.text[:200])!r}"
    )

    # --- teardown of the slow chain, in the body (see _teardown_distribution) ------------------
    _teardown_distribution(cf, dist["Id"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
