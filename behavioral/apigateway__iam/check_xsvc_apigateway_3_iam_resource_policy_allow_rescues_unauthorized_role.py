"""xsvc-apigateway-3-iam-resource-policy-allow-rescues-unauthorized-role."""
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

CHECK = "xsvc-apigateway-3-iam-resource-policy-allow-rescues-unauthorized-role"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "iam", "sts"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A same-account role with no identity policy is refused by the AWS_IAM stage until an API
    resource policy Allowing that role ARN is redeployed, after which it alone is served; a second
    unpermitted role the policy does not name stays refused."""
    api = _create_iam_api(ctx)
    rescued = _create_role(ctx, api["account_id"])   # no identity policy
    bystander = _create_role(ctx, api["account_id"])  # no identity policy, not in resource policy
    rescued_creds = _assume(ctx, rescued["arn"])
    bystander_creds = _assume(ctx, bystander["arn"])
    _await_stage_live(ctx, api)

    def _denied_no_identity(resp, who) -> bool:
        status, headers, body = resp
        return (status == 403 and headers.get("x-amzn-errortype") == "AccessDeniedException"
                and json.loads(body)["Message"].startswith(f"User: {who['session_arn']} is not authorized")
                and json.loads(body)["Message"].endswith(
                    f"{api['api_id']}/{_STAGE}/GET/widgets because no identity-based policy allows the execute-api:Invoke action"))

    before = _invoke(ctx, api["url"], rescued_creds)
    assert _denied_no_identity(before, rescued), f"before any resource policy the role got {before!r}"

    _apply_resource_policy(ctx, api["api_id"], [{
        "Effect": "Allow",
        "Principal": {"AWS": rescued["arn"]},
        "Action": "execute-api:Invoke",
        "Resource": f"execute-api:/{_STAGE}/GET/widgets",
    }])
    stored = json.loads(json.loads('"' + ctx.client("apigateway").get_rest_api(restApiId=api["api_id"])["policy"] + '"'))
    assert stored["Statement"][0]["Resource"] == api["arn_prefix"] + "/GET/widgets", (
        f"stored resource policy did not expand the execute-api:/ shorthand: {stored!r}"
    )

    status, _, body = _await(
        lambda: _invoke(ctx, api["url"], rescued_creds),
        lambda r: r[0] == 200,
        "the resource-policy-allowed role to be served after redeploy",
    )
    assert json.loads(body) == {"served": "GET"}, f"rescued GET body was {body!r}"

    # The bystander is in the same account, equally unpermitted, and not named by the policy.
    for attempt in range(_STREAK):
        resp = _invoke(ctx, api["url"], bystander_creds)
        assert _denied_no_identity(resp, bystander), (
            f"attempt {attempt}: role NOT named in the resource policy got {resp!r}"
        )


_STAGE = "test"
_SESSION = "sim2real-agwiam"
_STREAK = 3


def _delete_rest_api(apigw, api_id: str, budget_s: float = 120.0) -> None:
    """DeleteRestApi is rate-limited per ACCOUNT (TooManyRequestsException under concurrent
    teardown); retry within a bound, then say so on stdout."""
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
