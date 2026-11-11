"""deploy-notebook-instance-cloudformation-presigned-url-accessible."""
from __future__ import annotations

import http.cookiejar
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "deploy-notebook-instance-cloudformation-presigned-url-accessible"
GROUP = "deploy"
SERVICES = ["sagemaker"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  NotebookRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonSageMakerFullAccess
      Tags:
        - Key: sim2real
          Value: {check_id}
  NotebookInstance:
    Type: AWS::SageMaker::NotebookInstance
    Properties:
      NotebookInstanceName: {notebook_name}
      InstanceType: ml.t3.medium
      RoleArn: !GetAtt NotebookRole.Arn
      Tags:
        - Key: sim2real
          Value: {check_id}
Outputs:
  NotebookInstanceNameOut:
    Value: {notebook_name}
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A NotebookInstance deployed via CloudFormation reaches InService, and a presigned URL
    generated against it is actually accepted by the notebook's HTTPS front door -- proving the
    CFN-provisioned resource is usable, not just that the stack echoed CREATE_COMPLETE."""
    sm = ctx.client("sagemaker")
    notebook_name = ctx.unique_name("sim2real-nbi-")
    template = _TEMPLATE.format(notebook_name=notebook_name, check_id=CHECK)
    _deploy_cfn(ctx, template)

    # CloudFormation's own resource-creation wait for AWS::SageMaker::NotebookInstance should
    # already imply InService, but we re-confirm the actual data-plane-adjacent state directly
    # against SageMaker rather than trusting the stack status alone.
    status = _poll_until(
        lambda: sm.describe_notebook_instance(NotebookInstanceName=notebook_name)["NotebookInstanceStatus"],
        lambda status: status in ("InService", "Failed"),
        timeout_s=900,
        interval_s=15,
    )
    assert status == "InService", f"notebook instance did not reach InService (status={status!r})"

    resp = sm.create_presigned_notebook_instance_url(NotebookInstanceName=notebook_name)
    url = resp["AuthorizedUrl"]
    assert not (p := ctx.published_url_mismatch(url, labels=("notebook", ctx.region, "sagemaker"))), p

    # The terminal read: the presigned URL must actually be accepted by the notebook's own
    # HTTPS front door, not merely look like a URL -- a control-plane echo is not evidence the
    # deployed instance is usable. The auth hop sets a session cookie and redirects to the
    # notebook host, which needs it back; a redirect to a sign-in page on another host is a
    # refusal, so the chain must end in the presigned URL's own zone.
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    req = _routed_request(ctx, url, headers={"User-Agent": "sim2real-behavioral-check/1.0"})
    try:
        with opener.open(req, timeout=30) as http_resp:
            final_url, status_code = http_resp.geturl(), http_resp.status
    except urllib.error.HTTPError as exc:
        final_url, status_code = exc.geturl(), exc.code
    assert status_code < 400, f"presigned notebook URL was not accepted, HTTP status {status_code}"
    assert _same_zone(final_url, url), (
        "the presigned notebook URL should redirect to the notebook's own host, not a sign-in "
        f"page or an unrelated host: status={status_code} final_url={(final_url or '')[:200]}"
    )


def _same_zone(final_url, presigned_url) -> bool:
    """Whether a redirect chain ended in the presigned URL's own zone: every host label after the
    first (service label, region, domain) is the presigned host's."""
    final = (urlsplit(final_url or "").hostname or "").split(".")
    origin = (urlsplit(presigned_url).hostname or "").split(".")
    return len(origin) > 2 and all(origin) and final[1:] == origin[1:]


def _deploy_cfn(ctx, template: str) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-nbi-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})
    return stack_name


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
