"""xsvc-apigateway-3-iam-resource-policy-source-ip-any-cidr-allow-invokes."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigateway-3-iam-resource-policy-source-ip-any-cidr-allow-invokes"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "iam", "sts"]

_EVERYWHERE = "0.0.0.0/0"
# RFC 5737 TEST-NET-1: documentation-only, never routed, so no real caller is ever inside it.
_TEST_NET = "192.0.2.0/24"


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A resource-policy Allow on IpAddress 0.0.0.0/0 serves a role with no identity policy, and
    narrowing it to 192.0.2.0/24, which excludes the caller, refuses the role again."""
    api = _create_iam_api(ctx)
    role = _create_role(ctx, api["account_id"])  # no identity policy: the resource policy is the only grant
    creds = _assume(ctx, role["arn"])
    _await_stage_live(ctx, api)

    # AWS masks all but the last four digits of the account id in the resource ARN.
    masked_account = "*" * 8 + api["account_id"][-4:]
    want_message = (
        f"User: {role['session_arn']} is not authorized to perform: execute-api:Invoke on "
        f"resource: arn:aws:execute-api:{ctx.region}:{masked_account}:{api['api_id']}/"
        f"{_STAGE}/GET/widgets because no identity-based policy allows the execute-api:Invoke action"
    )

    status, headers, body = _invoke(ctx, api["url"], creds)
    assert status == 403 and headers.get("x-amzn-errortype") == "AccessDeniedException", (
        f"before any resource policy the role got {status!r} {headers.get('x-amzn-errortype')!r} {body!r}"
    )
    assert json.loads(body)["Message"] == want_message, (
        f"before any resource policy the denial message was {body!r}"
    )

    def _allow_from(cidr: str) -> dict:
        return {
            "Effect": "Allow",
            "Principal": {"AWS": role["arn"]},
            "Action": "execute-api:Invoke",
            "Resource": f"execute-api:/{_STAGE}/GET/widgets",
            "Condition": {"IpAddress": {"aws:SourceIp": cidr}},
        }

    _apply_resource_policy(ctx, api["api_id"], [_allow_from(_EVERYWHERE)])
    status, _, body = _await(
        lambda: _invoke(ctx, api["url"], creds),
        lambda r: r[0] == 200,
        f"the IpAddress {_EVERYWHERE} Allow to serve the role after redeploy",
    )
    assert json.loads(body) == {"served": "GET"}, f"allowed GET body was {body!r}"

    # Narrow only the CIDR. The caller is outside TEST-NET-1, so the only grant does not apply.
    _apply_resource_policy(ctx, api["api_id"], [_allow_from(_TEST_NET)])
    status, headers, body = _await(
        lambda: _invoke(ctx, api["url"], creds),
        lambda r: r[0] == 403,
        f"the role to be refused once the Allow requires IpAddress {_TEST_NET}",
    )
    assert headers.get("x-amzn-errortype") == "AccessDeniedException", (
        f"narrowed-allow x-amzn-ErrorType was {headers.get('x-amzn-errortype')!r}"
    )
    message = json.loads(body)["Message"]
    assert message == want_message, (
        f"narrowed-allow denial message was {message!r}"
    )
    assert "served" not in body, f"refused GET leaked the integration response: {body!r}"


_STAGE = "test"
_SESSION = "sim2real-agwiam"
_STREAK = 3


def _delete_rest_api(apigw, api_id: str, budget_s: float = 120.0) -> None:
    """Delete the REST API, retrying TooManyRequestsException (DeleteRestApi is rate-limited per
    account) every 10 s up to budget_s; NotFoundException counts as deleted, anything else raises."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() > deadline:
                raise RuntimeError(f"rest api {api_id} not deleted: {code}") from e
            time.sleep(10)


def _create_iam_api(ctx, methods=("GET",)) -> dict:
    apigw = ctx.client("apigateway")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-xsvc-agwiam-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(apigw, api_id))
    resources = [r for page in apigw.get_paginator("get_resources").paginate(restApiId=api_id)
                 for r in page["items"]]
    root_id = next(r["id"] for r in resources if r["path"] == "/")
    res_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")["id"]
    for m in methods:
        apigw.put_method(restApiId=api_id, resourceId=res_id, httpMethod=m,
                         authorizationType="AWS_IAM")
        apigw.put_method_response(restApiId=api_id, resourceId=res_id, httpMethod=m,
                                  statusCode="200")
        apigw.put_integration(restApiId=api_id, resourceId=res_id, httpMethod=m, type="MOCK",
                              requestTemplates={"application/json": '{"statusCode": 200}'})
        apigw.put_integration_response(restApiId=api_id, resourceId=res_id, httpMethod=m,
                                       statusCode="200",
                                       responseTemplates={"application/json": json.dumps({"served": m})})
    apigw.create_deployment(restApiId=api_id, stageName=_STAGE)
    return {
        "api_id": api_id,
        "account_id": account_id,
        "url": f"{ctx.rest_api_url(api_id, _STAGE)}/widgets",
        "arn_prefix": f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/{_STAGE}",
    }


def _create_role(ctx, account_id: str, allow_resources=None) -> dict:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-agwiam-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if allow_resources:
        _attach_invoke(ctx, name, allow_resources)
    return {"name": name, "arn": arn,
            "session_arn": f"arn:aws:sts::{account_id}:assumed-role/{name}/{_SESSION}"}


def _attach_invoke(ctx, role_name: str, resources) -> None:
    iam = ctx.client("iam")
    iam.put_role_policy(RoleName=role_name, PolicyName="invoke-execute-api", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "execute-api:Invoke", "Resource": list(resources)}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="invoke-execute-api"))


def _apply_resource_policy(ctx, api_id: str, statements) -> None:
    """Replace the API's resource policy and redeploy the stage - a policy change takes effect
    on the stage only through a new deployment."""
    apigw = ctx.client("apigateway")
    doc = {"Version": "2012-10-17", "Statement": list(statements)}
    apigw.update_rest_api(restApiId=api_id, patchOperations=[
        {"op": "replace", "path": "/policy", "value": json.dumps(doc)}])
    apigw.create_deployment(restApiId=api_id, stageName=_STAGE)


def _await_stage_live(ctx, api: dict) -> None:
    """Barrier: a brand-new deployment is not instantly live at the edge. A throwaway role allowed
    on every method must be served before any denial is asserted, so a 403 observed afterwards is
    a decision about the caller, never a stage that has not propagated yet."""
    probe = _create_role(ctx, api["account_id"], allow_resources=[api["arn_prefix"] + "/*"])
    creds = _assume(ctx, probe["arn"])
    _await(lambda: _invoke(ctx, api["url"], creds), lambda r: r[0] == 200,
           "the new stage to serve an allowed probe role")


def _assume(ctx, role_arn: str, timeout_s: float = 120.0) -> Credentials:
    # IAM propagation of a new role's trust exposes no condition to poll; the bounded
    # AccessDenied retry at first use is what makes this correct.
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)["Credentials"]
            return Credentials(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _invoke(ctx, url: str, creds, method: str = "GET"):
    headers = {}
    if creds is not None:
        req = AWSRequest(method=method, url=url)
        SigV4Auth(creds, "execute-api", ctx.region).add_auth(req)
        headers = dict(req.headers)
    request = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode()


def _await(probe, pred, what: str, timeout_s: float = 240.0, interval_s: float = 3.0):
    """Poll the live endpoint until `pred` holds for _STREAK consecutive responses."""
    deadline = time.monotonic() + timeout_s
    streak, last = 0, None
    while time.monotonic() < deadline:
        last = probe()
        streak = streak + 1 if pred(last) else 0
        if streak >= _STREAK:
            return last
        time.sleep(interval_s if streak == 0 else 1.0)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
