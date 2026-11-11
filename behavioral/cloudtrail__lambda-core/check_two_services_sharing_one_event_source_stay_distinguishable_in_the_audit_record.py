"""two-services-sharing-one-event-source-stay-distinguishable-in-the-audit-record."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "two-services-sharing-one-event-source-stay-distinguishable-in-the-audit-record"
GROUP = "eventing"
SERVICES = ["cloudtrail", "lambda-core"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# Both Smithy models (lambda and lambda-core) declare this cloudTrailEventSource.
_SHARED_EVENT_SOURCE = "lambda.amazonaws.com"
_CORE_EVENT_NAME = "CreateNetworkConnector"
# Classic Lambda's eventName carries its per-operation REST URI version suffix.
_LAMBDA_EVENT_NAME = "PublishLayerVersion20181031"

_INDEX_BUDGET_S = 255.0  # CloudTrail event history indexing latency
_ROLE_PROPAGATION_WAIT_S = 120.0
_CONNECTOR_ACTIVE_WAIT_S = 600.0  # a fresh connector stays PENDING for minutes
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

_OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"
# Two error messages AWS returns for the same lag: a fresh operator role or its policy is not yet
# visible to the service that assumes it.
_NOT_PROPAGATED = ("invalid ConnectorOperatorRole permissions", "unable to assume the provided")

def _lookup_all(ct, **kw):
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
    raise AssertionError(
        f"{DATAPLANE_MARKER}: LookupEvents paged past {_PAGE_CEILING} pages without exhausting"
    )


def _await_record(ct, event_name, needle, budget_s=_INDEX_BUDGET_S):
    """Poll event history for a record of `event_name` whose serialised form contains `needle`."""
    deadline = time.monotonic() + budget_s
    examined = 0
    while True:
        events = _lookup_all(
            ct, LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}]
        )
        examined = len(events)
        for ev in events:
            if needle in ev.get("CloudTrailEvent", ""):
                return json.loads(ev["CloudTrailEvent"]), ev
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: no {event_name} record naming {needle!r} within "
                f"{budget_s:.0f}s; expected 1, actual 0 of {examined} {event_name} records examined"
            )
        time.sleep(_POLL_INTERVAL_S)


def _tiny_layer_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("python/simparity_marker.py", "MARKER = 'simparity'\n")
    return buf.getvalue()


def _delete_layer_version(lam, layer_name, version):
    try:
        lam.delete_layer_version(LayerName=layer_name, VersionNumber=version)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_network_connector(core, connector_id, timeout_s=600.0):
    # A connector is refused deletion (ResourceConflictException) while it is still PENDING.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            core.delete_network_connector(Identifier=connector_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(15)


def _detach_operator_policy(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _delete_operator_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _default_vpc_network(ec2, *, ctx):
    """A subnet and the default security group the connector can attach to (nothing created)."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, (
        "the account must have a default VPC for the network connector to attach to: expected >=1, "
        "actual 0 -- create one in-check if this ever fails rather than skipping"
    )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    assert subnets, f"the shared network {vpc_id} must have at least one subnet: expected >=1, actual 0"
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    assert sgs, f"the shared network {vpc_id} must have a default security group: expected >=1, actual 0"
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]


def _operator_role(ctx, iam):
    """An IAM role with AWSLambdaNetworkConnectorOperatorPolicy attached, usable as OperatorRole."""
    role_name = ctx.unique_name("simparity-ct-lncrole-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_operator_role(iam, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: _detach_operator_policy(iam, role_name))

    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        arns = [
            p["PolicyArn"]
            for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        ]
        if _OPERATOR_POLICY_ARN in arns:
            break
        time.sleep(2)
    return role_arn


def _create_connector_with_retry(core, budget_s=_ROLE_PROPAGATION_WAIT_S, **kwargs):
    """CreateNetworkConnector, retried while a freshly attached operator-role policy propagates."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            return core.create_network_connector(**kwargs)
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message") or ""
            if not any(m in msg for m in _NOT_PROPAGATED) or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _await_not_pending(core, connector_id, budget_s=_CONNECTOR_ACTIVE_WAIT_S):
    """Wait the connector out of PENDING: Delete is refused with ResourceConflictException while
    PENDING, and the bounded cleanup delete would otherwise race that state."""
    deadline = time.monotonic() + budget_s
    state = "PENDING"
    while time.monotonic() < deadline:
        state = core.get_network_connector(Identifier=connector_id)["State"]
        if state != "PENDING":
            return state
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"{DATAPLANE_MARKER}: connector {connector_id} stayed PENDING for {budget_s:.0f}s"
    )


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """Two distinct services sharing one CloudTrail event source (lambda-core and lambda) are both
    audited under lambda.amazonaws.com, yet stay separable: distinct eventName and eventID, each
    record naming only its own resource.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    core = ctx.client("lambda-core")
    lam = ctx.client("lambda")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ct = ctx.client("cloudtrail")

    # ---- the lambda-core write --------------------------------------------------------------------
    subnet_id, sg_id = _default_vpc_network(ec2, ctx=ctx)
    role_arn = _operator_role(ctx, iam)
    connector_name = ctx.unique_name("simparity-ct-conn-")
    created = _create_connector_with_retry(
        core,
        Name=connector_name,
        Configuration={
            "VpcEgressConfiguration": {
                "SubnetIds": [subnet_id],
                "SecurityGroupIds": [sg_id],
                "NetworkProtocol": "IPv4",
                "AssociatedComputeResourceTypes": ["MicroVm"],
            }
        },
        # Documented optional, but AWS rejects CreateNetworkConnector without it.
        OperatorRole=role_arn,
        Tags={"sim2real": CHECK},
    )
    connector_id = created.get("Id")
    assert connector_id, (
        "CreateNetworkConnector must return an identifier the record can be joined on: expected a "
        f"non-empty Id, actual {created!r}"
    )
    ctx.on_cleanup(lambda: _delete_network_connector(core, connector_id))

    # ---- the ordinary-Lambda write, the sibling positive control ----------------------------------
    layer_name = ctx.unique_name("simparity-ct-layer-")
    published = lam.publish_layer_version(
        LayerName=layer_name,
        Description=CHECK,
        Content={"ZipFile": _tiny_layer_zip()},
        CompatibleRuntimes=["python3.12"],
    )
    layer_version = published["Version"]
    ctx.on_cleanup(lambda: _delete_layer_version(lam, layer_name, layer_version))
    assert published["LayerArn"].startswith(f"arn:aws:lambda:{ctx.region}:{account_id}:layer:"), (
        "the layer ARN must be in the lambda namespace for this account and region: expected a "
        f"prefix arn:aws:lambda:{ctx.region}:{account_id}:layer:, actual {published['LayerArn']!r}"
    )

    # ---- terminal reads, both at CloudTrail's index -----------------------------------------------
    core_record, core_event = _await_record(ct, _CORE_EVENT_NAME, connector_name)
    lambda_record, lambda_event = _await_record(ct, _LAMBDA_EVENT_NAME, layer_name)

    # The shared-source leg -- the point of the check.
    assert core_record.get("eventSource") == _SHARED_EVENT_SOURCE, (
        "lambda-core declares cloudTrailEventSource 'lambda.amazonaws.com' in its Smithy model even "
        "though it is a DIFFERENT service (com.amazonaws.lambdacore#LambdaCoreApiService), so its "
        f"records must carry that source: expected {_SHARED_EVENT_SOURCE!r}, actual "
        f"{core_record.get('eventSource')!r} (a target keyed on the service or crate name "
        "emits 'lambdacore.amazonaws.com' here and fails)"
    )
    assert lambda_record.get("eventSource") == _SHARED_EVENT_SOURCE, (
        f"ordinary Lambda's records must carry the same source: expected {_SHARED_EVENT_SOURCE!r}, "
        f"actual {lambda_record.get('eventSource')!r}"
    )
    assert core_event["EventSource"] == lambda_event["EventSource"], (
        "the two services' records must agree on EventSource in the LookupEvents summary too, not "
        f"only inside CloudTrailEvent: actual {core_event['EventSource']!r} vs "
        f"{lambda_event['EventSource']!r}"
    )

    # The separability legs -- one source must not mean one record.
    assert core_record.get("eventName") == _CORE_EVENT_NAME, (
        f"eventName: expected {_CORE_EVENT_NAME!r}, actual {core_record.get('eventName')!r}"
    )
    assert lambda_record.get("eventName") == _LAMBDA_EVENT_NAME, (
        f"eventName: expected {_LAMBDA_EVENT_NAME!r}, actual {lambda_record.get('eventName')!r}"
    )
    assert core_record.get("eventID") != lambda_record.get("eventID"), (
        "two writes in two services must produce two DISTINCT records even though they share an "
        f"event source: expected different eventIDs, actual both {core_record.get('eventID')!r} "
        "(a target that collapses the two services into one audit entry fails here)"
    )
    assert connector_name in json.dumps(core_record.get("requestParameters") or {}), (
        "the lambda-core record's requestParameters must name its own resource: expected "
        f"{connector_name!r} inside "
        f"{json.dumps(core_record.get('requestParameters') or {})[:200]!r}, actual absent"
    )
    assert layer_name in json.dumps(lambda_record.get("requestParameters") or {}), (
        "the Lambda record's requestParameters must name its own resource: expected "
        f"{layer_name!r} inside "
        f"{json.dumps(lambda_record.get('requestParameters') or {})[:200]!r}, actual absent"
    )
    # Cross-contamination: neither record may name the other's resource.
    assert layer_name not in json.dumps(core_record), (
        f"the lambda-core record must not mention the layer: expected {layer_name!r} absent, actual "
        "present"
    )
    assert connector_name not in json.dumps(lambda_record), (
        f"the Lambda record must not mention the connector: expected {connector_name!r} absent, "
        "actual present"
    )

    # Both are management events, in this region, for this account, with no error.
    for label, rec in (("lambda-core", core_record), ("lambda", lambda_record)):
        assert rec.get("eventCategory") == "Management", (
            f"[{label}] eventCategory: expected 'Management', actual {rec.get('eventCategory')!r}"
        )
        assert rec.get("awsRegion") == ctx.region, (
            f"[{label}] awsRegion: expected {ctx.region!r}, actual {rec.get('awsRegion')!r}"
        )
        assert rec.get("recipientAccountId") == account_id, (
            f"[{label}] recipientAccountId: expected {account_id!r}, actual "
            f"{rec.get('recipientAccountId')!r}"
        )
        assert rec.get("errorCode") is None, (
            f"[{label}] a successful write must record no errorCode: expected None, actual "
            f"{rec.get('errorCode')!r}"
        )
        assert rec.get("readOnly") is False, (
            f"[{label}] both operations are writes, so readOnly must be False: actual "
            f"{rec.get('readOnly')!r}"
        )

    # ---- let the connector leave PENDING before the bounded cleanup has to delete it --------------
    _await_not_pending(core, connector_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
