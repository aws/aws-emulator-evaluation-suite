"""sar-prepared-template-serves-the-published-body."""
from __future__ import annotations

import json
import time
import urllib.request

import yaml

from behavioral_harness import tags

CHECK = "sar-prepared-template-serves-the-published-body"
GROUP = "template-preparation"
SERVICES = ["serverlessrepo"]

_TEMPLATE_WAIT_S = 120
_FETCH_TIMEOUT_S = 30

_SAM_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Transform": "AWS::Serverless-2016-10-31",
    "Parameters": {"QueueNameParam": {"Type": "String"}},
    "Resources": {
        "Q": {
            "Type": "AWS::SQS::Queue",
            "Properties": {"QueueName": {"Ref": "QueueNameParam"}},
        }
    },
    "Outputs": {"QueueUrl": {"Value": {"Ref": "Q"}}},
}


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A prepared CloudFormation template reaches ACTIVE before its ExpirationTime, and its presigned
    TemplateUrl serves, without AWS credentials, a body that parses to the published template; preparing
    the version again yields a new TemplateId serving the same body."""
    sar = ctx.client("serverlessrepo")

    app_name = ctx.unique_name("sim2real-behav-sartpl-")
    created = sar.create_application(
        Name=app_name,
        Author="sim2real-behav",
        Description="sim2real SAR template preparation check",
        TemplateBody=json.dumps(_SAM_TEMPLATE),
        SemanticVersion="1.0.0",
    )
    app_id = created["ApplicationId"]
    ctx.on_cleanup(lambda: sar.delete_application(ApplicationId=app_id))

    prepared = sar.create_cloud_formation_template(ApplicationId=app_id, SemanticVersion="1.0.0")
    template_id = prepared["TemplateId"]
    assert prepared["Status"] in ("PREPARING", "ACTIVE"), (
        f"freshly created template is {prepared['Status']!r}"
    )
    assert prepared["ApplicationId"] == app_id, (
        f"template belongs to {prepared['ApplicationId']!r}, published {app_id!r}"
    )
    assert prepared["SemanticVersion"] == "1.0.0", (
        f"template was cut for version {prepared['SemanticVersion']!r}"
    )

    active = _await_active(sar, app_id, template_id)
    assert active["Status"] == "ACTIVE", f"template settled as {active['Status']!r}, not ACTIVE"
    assert active["TemplateId"] == template_id, (
        f"read back template {active['TemplateId']!r}, asked for {template_id!r}"
    )
    assert active["SemanticVersion"] == "1.0.0", (
        f"read back version {active['SemanticVersion']!r}"
    )
    assert active["ExpirationTime"] > active["CreationTime"], (
        f"template expires at {active['ExpirationTime']!r}, created {active['CreationTime']!r}"
    )

    # The URL is presigned: a plain HTTPS GET with no AWS credentials of our own must serve it.
    served = _fetch(ctx, active["TemplateUrl"])
    assert served.strip(), f"TemplateUrl {active['TemplateUrl']!r} served an empty body"

    document = yaml.safe_load(served)
    assert document == _SAM_TEMPLATE, (
        f"served template differs from the published one: {document!r}"
    )

    # Every published version can be prepared again, and the second artifact is a distinct id
    # serving the same body — SAR treats a prepared template as a cache entry, not as the version.
    again = sar.create_cloud_formation_template(ApplicationId=app_id, SemanticVersion="1.0.0")
    assert again["TemplateId"] != template_id, (
        f"re-preparing returned the same TemplateId {template_id!r}"
    )
    second = _await_active(sar, app_id, again["TemplateId"])
    assert yaml.safe_load(_fetch(ctx, second["TemplateUrl"])) == _SAM_TEMPLATE, (
        "the second prepared template does not serve the published body"
    )


def _await_active(sar, app_id: str, template_id: str) -> dict:
    deadline = time.time() + _TEMPLATE_WAIT_S
    while True:
        got = sar.get_cloud_formation_template(ApplicationId=app_id, TemplateId=template_id)
        if got["Status"] != "PREPARING":
            return got
        assert time.time() < deadline, (
            f"template {template_id!r} still PREPARING after {_TEMPLATE_WAIT_S}s"
        )
        time.sleep(3)


def _fetch(ctx, url: str) -> str:
    target_url, route_headers = ctx.endpoint_route(url)
    with urllib.request.urlopen(urllib.request.Request(target_url, headers=route_headers), timeout=_FETCH_TIMEOUT_S) as response:  # noqa: S310
        assert response.status == 200, f"GET {url!r} returned {response.status}"
        return response.read().decode("utf-8")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
