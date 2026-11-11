"""function-sdk-cloudwatch-get-otel-enrichment-answers."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "function-sdk-cloudwatch-get-otel-enrichment-answers"
GROUP = "data-plane"
SERVICES = ["cloudwatch", "lambda"]

_RUNTIME = "python3.12"
_SOURCE_FILE = "index.py"

# The GetOTelEnrichment slice of the CloudWatch service model, shipped in the deployment package
# and named by AWS_DATA_PATH, so the call does not depend on which botocore the runtime bundles.
# "protocol" is the fallback for a botocore that predates the "protocols" list; a newer one picks
# the first entry of "protocols" it supports, as it does for its own bundled model.
_MODEL = {'version': '2.0',
 'metadata': {'apiVersion': '2010-08-01',
              'awsQueryCompatible': {},
              'endpointPrefix': 'monitoring',
              'jsonVersion': '1.0',
              'protocol': 'query',
              'protocols': ['smithy-rpc-v2-cbor', 'json', 'query'],
              'serviceAbbreviation': 'CloudWatch',
              'serviceId': 'CloudWatch',
              'signatureVersion': 'v4',
              'targetPrefix': 'GraniteServiceVersion20100801',
              'uid': 'monitoring-2010-08-01',
              'xmlNamespace': 'http://monitoring.amazonaws.com/doc/2010-08-01/',
              'auth': ['aws.auth#sigv4']},
 'operations': {'GetOTelEnrichment': {'name': 'GetOTelEnrichment',
                                      'http': {'method': 'POST', 'requestUri': '/'},
                                      'input': {'shape': 'GetOTelEnrichmentInput'},
                                      'output': {'shape': 'GetOTelEnrichmentOutput',
                                                 'resultWrapper': 'GetOTelEnrichmentResult'}}},
 'shapes': {'GetOTelEnrichmentInput': {'type': 'structure', 'members': {}},
            'GetOTelEnrichmentOutput': {'type': 'structure',
                                        'required': ['Status'],
                                        'members': {'Status': {'shape': 'OTelEnrichmentStatus'},
                                                    'IncludeFilters': {'shape': 'OTelEnrichmentMetricSelectorList'},
                                                    'ExcludeFilters': {'shape': 'OTelEnrichmentMetricSelectorList'},
                                                    'CreatedAt': {'shape': 'Timestamp'},
                                                    'UpdatedAt': {'shape': 'Timestamp'}}},
            'MetricName': {'type': 'string', 'max': 255, 'min': 1},
            'Namespace': {'type': 'string', 'max': 255, 'min': 1, 'pattern': '[^:].*'},
            'OTelEnrichmentMetricNameList': {'type': 'list',
                                             'member': {'shape': 'MetricName'},
                                             'max': 100,
                                             'min': 0},
            'OTelEnrichmentMetricSelector': {'type': 'structure',
                                             'required': ['Namespace'],
                                             'members': {'Namespace': {'shape': 'Namespace'},
                                                         'MetricNames': {'shape': 'OTelEnrichmentMetricNameList'}}},
            'OTelEnrichmentMetricSelectorList': {'type': 'list',
                                                 'member': {'shape': 'OTelEnrichmentMetricSelector'},
                                                 'max': 100,
                                                 'min': 0},
            'OTelEnrichmentStatus': {'type': 'string', 'enum': ['Running', 'Stopped']},
            'Timestamp': {'type': 'timestamp'}}}
_MODEL_PATH = "models/cloudwatch/2010-08-01/service-2.json"
_HANDLER = """\
import boto3


def handler(event, context):
    out = boto3.client("cloudwatch").get_otel_enrichment()
    status = out.get("Status")
    return {"status": status, "status_type": type(status).__name__,
            "keys": sorted(k for k in out if k != "ResponseMetadata")}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function's read-only GetOTelEnrichment answers the account's enrichment status: the
    same Status string the caller's own GetOTelEnrichment reads around the invoke.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetOTelEnrichment.html
    """
    # GetOTelEnrichment is account-scoped and takes no resource.
    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": ["cloudwatch:GetOTelEnrichment"], "Resource": "*"},
    ])
    fn = _function(ctx, role["arn"], _HANDLER, extra={_MODEL_PATH: json.dumps(_MODEL)},
                   environment={"AWS_DATA_PATH": "/var/task/models"})

    cw = ctx.client("cloudwatch")
    before = cw.get_otel_enrichment()["Status"]
    out = _invoke_granted(ctx, fn["name"], {})
    after = cw.get_otel_enrichment()["Status"]
    assert "Status" in out["keys"], f"GetOTelEnrichment must answer a Status, answered {out!r}"
    assert out["status_type"] == "str", f"Status must be a string, got {out!r}"
    # The status is account-wide and another run in the account may toggle it during the invoke,
    # so the function's answer must match the caller's read on one side of it.
    seen = sorted({before, after})
    assert out["status"] in seen, (
        f"the function read Status {out['status']!r}, expected the caller's read {seen!r} "
        f"(before the invoke {before!r}, after {after!r})")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _zip(code: str, extra=None) -> bytes:
    """The deployment package: the handler module plus ``extra`` files keyed by archive path."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(_SOURCE_FILE, textwrap.dedent(code))
        for path, body in (extra or {}).items():
            zf.writestr(path, body)
    return buf.getvalue()


def _execution_role(ctx, statements) -> dict:
    """A Lambda execution role holding exactly ``statements`` and no logs: grant, so the function
    never creates a log group that could outlive the check."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
        ctx.on_cleanup(_teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
            "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"], "id": role["RoleId"]}


def _function(ctx, role_arn, code, *, timeout=60, memory=256, extra=None, environment=None) -> dict:
    """A function from ``code``, created through the role-propagation window and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": _RUNTIME, "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code, extra)}, "Timeout": timeout,
              "MemorySize": memory, "Tags": {"sim2real": CHECK}}
    if environment:
        kwargs["Environment"] = {"Variables": environment}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    out = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"),
                 timeout_s=90, interval_s=1, what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return {"name": name, "arn": out["FunctionArn"]}


def _invoke(ctx, fn, event=None, lam=None) -> tuple:
    """(FunctionError or None, decoded payload) of one RequestResponse invoke of ``event``."""
    lam = lam or ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse",
                      Payload=json.dumps(event or {}).encode())
    raw = resp["Payload"].read()
    return resp.get("FunctionError"), (json.loads(raw) if raw else None)


def _denied(result) -> bool:
    """Whether an invoke's payload shows a refusal the role's still-propagating grants explain."""
    text = json.dumps(result[1])
    return "AccessDenied" in text or '"status": 403' in text or '"code": "403"' in text


def _invoke_granted(ctx, fn, event) -> dict:
    """The payload of ``fn`` once the role's grants are effective; any other failure raises."""
    err, out = _poll(lambda: _invoke(ctx, fn, event), lambda r: not _denied(r),
                     timeout_s=90, interval_s=5, what="the role's cloudwatch grants are effective")
    assert err is None, f"the function failed: {err!r} {out!r}"
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
