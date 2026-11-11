"""studio-lifecycle-and-tag-roundtrip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "studio-lifecycle-and-tag-roundtrip"
GROUP = 'studios'
SERVICES = ['emr']

# ===== helpers =====
# The network and role are real because a studio cannot be created against unresolvable ids.
# Everything created is free of charge: Studio is billed only through attached workspaces and
# clusters, and no NAT gateway, Elastic IP or cluster is created.

VPC_CIDR = "10.192.0.0/16"
SUBNET_CIDR = "10.192.20.0/24"

# The two ports the EMR Studio networking contract requires on the workspace
# security group: 18888 to the engine security group, 443 for the Studio UI.
WORKSPACE_TO_ENGINE_PORT = 18888
HTTPS_PORT = 443

MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_EMR_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

# Codes EMR uses while a freshly created IAM role has not propagated yet, and
# while an ENI or route is still being reclaimed on the EC2 side.
_ROLE_PROPAGATION_CODES = {"InvalidRequestException", "ValidationException"}
_ROLE_PROPAGATION_HINTS = ("assume", "role", "not authorized", "invalid")


def _gone(fn, *codes):
    """Run a teardown call; return quietly only on the given not-found codes, raise the rest."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in codes:
            raise


def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn):
    """Invoke fn, asserting it is rejected; return the (code, message) pair."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the operation to be rejected, but it succeeded")


def _make_bucket(ctx, s3):
    """The studio's DefaultS3Location bucket. Registered FIRST so LIFO teardown
    removes it only after the studio that references it is gone."""
    bucket = ctx.unique_name("sim2real-behav-emr-studio-")

    def _cleanup() -> None:
        def _purge_and_delete() -> None:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                victims = [
                    {"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
                ]
                if victims:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": victims}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)

        _gone(_purge_and_delete, "NoSuchBucket")

    ctx.on_cleanup(_cleanup)
    # S3's own CreateBucket quirk, not a hardcoded target region: us-east-1 rejects an
    # explicit LocationConstraint on CreateBucket, every other region requires one.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    return bucket


def _make_network(ctx, ec2):
    """A VPC, one subnet and the workspace/engine security-group pair.

    Torn down by a SINGLE registered cleanup because the two security groups
    reference each other: the cross-references must be revoked before either group
    can be deleted, and both groups before the subnet, and the subnet before the
    VPC. Splitting this across independent cleanups would deadlock on the cycle.
    """
    state = {"vpc": None, "subnet": None, "workspace_sg": None, "engine_sg": None}

    def _cleanup() -> None:
        ws, eng = state["workspace_sg"], state["engine_sg"]
        if ws and eng:
            _gone(
                lambda: ec2.revoke_security_group_egress(
                    GroupId=ws,
                    IpPermissions=[
                        {
                            "IpProtocol": "tcp",
                            "FromPort": WORKSPACE_TO_ENGINE_PORT,
                            "ToPort": WORKSPACE_TO_ENGINE_PORT,
                            "UserIdGroupPairs": [{"GroupId": eng}],
                        }
                    ],
                ),
                "InvalidPermission.NotFound", "InvalidGroup.NotFound",
            )
            _gone(
                lambda: ec2.revoke_security_group_ingress(
                    GroupId=eng,
                    IpPermissions=[
                        {
                            "IpProtocol": "tcp",
                            "FromPort": WORKSPACE_TO_ENGINE_PORT,
                            "ToPort": WORKSPACE_TO_ENGINE_PORT,
                            "UserIdGroupPairs": [{"GroupId": ws}],
                        }
                    ],
                ),
                "InvalidPermission.NotFound", "InvalidGroup.NotFound",
            )
        for group in (ws, eng):
            if group:
                # The studio's ENIs are released asynchronously after DeleteStudio; _delete_net
                # waits for them and retries DependencyViolation to its deadline.
                _gone(lambda group=group: _delete_net(ec2, "delete_security_group", GroupId=group),
                      "InvalidGroup.NotFound")
        if state["subnet"]:
            _gone(lambda: _delete_net(ec2, "delete_subnet", SubnetId=state["subnet"]), "InvalidSubnetID.NotFound")
        if state["vpc"]:
            _gone(lambda: _delete_net(ec2, "delete_vpc", VpcId=state["vpc"]), "InvalidVpcID.NotFound")

    ctx.on_cleanup(_cleanup)  # registered BEFORE anything in `state` exists

    tag_spec = [{"Key": t["Key"], "Value": t["Value"]} for t in MANAGED_TAGS]
    state["vpc"] = ec2.create_vpc(
        CidrBlock=VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_spec}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[state["vpc"]], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "region-name", "Values": [ctx.region]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
        if z["State"] == "available"
    ]
    assert azs, f"no available availability zone in {ctx.region}"
    state["subnet"] = ec2.create_subnet(
        VpcId=state["vpc"],
        CidrBlock=SUBNET_CIDR,
        AvailabilityZone=sorted(azs)[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_spec}],
    )["Subnet"]["SubnetId"]

    state["engine_sg"] = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-emr-studio-engine-"),
        Description="sim2real behavioral EMR Studio engine security group",
        VpcId=state["vpc"],
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag_spec}],
    )["GroupId"]
    state["workspace_sg"] = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-emr-studio-workspace-"),
        Description="sim2real behavioral EMR Studio workspace security group",
        VpcId=state["vpc"],
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag_spec}],
    )["GroupId"]

    # The networking contract EMR Studio documents and validates.
    ec2.authorize_security_group_ingress(
        GroupId=state["engine_sg"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": WORKSPACE_TO_ENGINE_PORT,
                "ToPort": WORKSPACE_TO_ENGINE_PORT,
                "UserIdGroupPairs": [{"GroupId": state["workspace_sg"]}],
            }
        ],
    )
    ec2.authorize_security_group_egress(
        GroupId=state["workspace_sg"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": WORKSPACE_TO_ENGINE_PORT,
                "ToPort": WORKSPACE_TO_ENGINE_PORT,
                "UserIdGroupPairs": [{"GroupId": state["engine_sg"]}],
            }
        ],
    )
    return state


def _make_service_role(ctx, iam, bucket):
    """The studio ServiceRole, with teardown registered before it is usable."""
    role_name = ctx.unique_name("sim2real-behav-emr-studio-role-")
    policy_name = "sim2real-behav-emr-studio"

    def _cleanup() -> None:
        _gone(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity")
        _gone(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")

    ctx.on_cleanup(_cleanup)

    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_EMR_TRUST_POLICY),
        Tags=MANAGED_TAGS,
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:CreateNetworkInterface",
                            "ec2:CreateNetworkInterfacePermission",
                            "ec2:DeleteNetworkInterface",
                            "ec2:DeleteNetworkInterfacePermission",
                            "ec2:DescribeNetworkInterfaces",
                            "ec2:DescribeTags",
                            "ec2:DescribeInstances",
                            "ec2:DescribeSubnets",
                            "ec2:DescribeVpcs",
                            "ec2:DescribeSecurityGroups",
                            "elasticmapreduce:ListInstances",
                            "elasticmapreduce:DescribeCluster",
                            "elasticmapreduce:ListSteps",
                        ],
                        "Resource": "*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:PutObject",
                            "s3:GetObject",
                            "s3:GetEncryptionConfiguration",
                            "s3:ListBucket",
                            "s3:DeleteObject",
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{bucket}",
                            f"arn:aws:s3:::{bucket}/*",
                        ],
                    },
                ],
            }
        ),
    )
    return arn


# ===== end helpers =====


def _service_message(text, message, service="AWSEditors"):
    """`text` as the EMR backend `service` words a refusal; only its per-call request id is taken
    from the actual message."""
    request_id = (message or "").rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    return (
        f"{text} (Service: {service}; Status Code: 400; Error Code: InvalidRequestException; "
        f"Request ID: {request_id}; Proxy: null)"
    )


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An EMR Studio round-trips create, describe, AddTags, RemoveTags (only the named key),
    UpdateStudio, ListStudios and DeleteStudio, after which reads and updates are refused.

    Reference: https://docs.aws.amazon.com/emr/latest/APIReference/API_CreateStudio.html"""
    emr = ctx.client("emr")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = _make_bucket(ctx, s3)
    net = _make_network(ctx, ec2)
    role_arn = _make_service_role(ctx, iam, bucket)

    studio_name = ctx.unique_name("sim2real-behav-emr-studio-")
    default_s3 = f"s3://{bucket}/studio/"
    created = {}

    def _cleanup_studio() -> None:
        if created.get("StudioId"):
            try:
                emr.delete_studio(StudioId=created["StudioId"])
            except ClientError as exc:
                err = exc.response["Error"]
                # An unknown studio is refused as InvalidRequestException "Studio does not exist."
                if not (err["Code"] == "InvalidRequestException"
                        and err.get("Message", "").startswith("Studio does not exist.")):
                    raise

    ctx.on_cleanup(_cleanup_studio)  # registered BEFORE CreateStudio is called

    # EMR probes the ServiceRole's assumability, which fails until a
    # seconds-old role has propagated. Retry only that classified failure, for up to 300s.
    deadline = time.monotonic() + 300
    last_err = None
    while True:
        try:
            created = emr.create_studio(
                Name=studio_name,
                Description="sim2real behavioral studio, initial description",
                AuthMode="IAM",
                VpcId=net["vpc"],
                SubnetIds=[net["subnet"]],
                ServiceRole=role_arn,
                WorkspaceSecurityGroupId=net["workspace_sg"],
                EngineSecurityGroupId=net["engine_sg"],
                DefaultS3Location=default_s3,
                Tags=MANAGED_TAGS,
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            message = exc.response.get("Error", {}).get("Message", "").lower()
            propagating = code in _ROLE_PROPAGATION_CODES and any(
                hint in message for hint in _ROLE_PROPAGATION_HINTS
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            last_err = exc
            time.sleep(2)
    assert created, f"CreateStudio never succeeded: {last_err}"

    studio_id = created["StudioId"]
    assert studio_id.startswith("es-"), (
        f"CreateStudio must return an EMR Studio id (es-...), got {studio_id!r}"
    )
    assert created.get("Url"), (
        f"CreateStudio must return the studio's Url, got {created!r}"
    )
    assert studio_id.lower() in created["Url"].lower(), (
        f"the studio Url must address this studio; url {created['Url']!r}, id "
        f"{studio_id!r}"
    )

    # --- describe: the full shape, echoing every submitted input.
    studio = emr.describe_studio(StudioId=studio_id)["Studio"]
    assert studio["StudioId"] == studio_id, f"unexpected describe response {studio!r}"
    assert studio["Name"] == studio_name, (
        f"DescribeStudio must echo the submitted Name, got {studio.get('Name')!r}"
    )
    assert studio["AuthMode"] == "IAM", (
        f"DescribeStudio must echo AuthMode IAM, got {studio.get('AuthMode')!r}"
    )
    assert studio["VpcId"] == net["vpc"], (
        f"DescribeStudio must echo the VpcId, got {studio.get('VpcId')!r}"
    )
    assert studio["SubnetIds"] == [net["subnet"]], (
        f"DescribeStudio must echo the submitted SubnetIds, got "
        f"{studio.get('SubnetIds')!r}"
    )
    assert studio["ServiceRole"] == role_arn, (
        f"DescribeStudio must echo the ServiceRole, got {studio.get('ServiceRole')!r}"
    )
    assert studio["WorkspaceSecurityGroupId"] == net["workspace_sg"], (
        f"DescribeStudio must echo WorkspaceSecurityGroupId, got "
        f"{studio.get('WorkspaceSecurityGroupId')!r}"
    )
    assert studio["EngineSecurityGroupId"] == net["engine_sg"], (
        f"DescribeStudio must echo EngineSecurityGroupId, got "
        f"{studio.get('EngineSecurityGroupId')!r}"
    )
    assert studio["DefaultS3Location"].rstrip("/") == default_s3.rstrip("/"), (
        f"DescribeStudio must echo DefaultS3Location, got "
        f"{studio.get('DefaultS3Location')!r}"
    )
    assert studio.get("CreationTime") is not None, (
        f"a created studio must carry a server-set CreationTime, got {studio!r}"
    )
    arn = studio.get("StudioArn", "")
    assert arn.startswith("arn:") and arn.endswith(f"/{studio_id}"), (
        f"StudioArn must be a well-formed ARN ending in the studio id, got {arn!r}"
    )
    assert f":{ctx.region}:" in arn, (
        f"StudioArn must name the request region {ctx.region!r}, got {arn!r}"
    )
    creation_tags = {t["Key"]: t["Value"] for t in studio.get("Tags", [])}
    for tag in MANAGED_TAGS:
        assert creation_tags.get(tag["Key"]) == tag["Value"], (
            f"tags supplied to CreateStudio must be readable; {tag!r} missing from "
            f"{creation_tags!r}"
        )

    def _studio_tags():
        return {
            t["Key"]: t["Value"]
            for t in emr.describe_studio(StudioId=studio_id)["Studio"].get("Tags", [])
        }

    # --- AddTags: written tags become readable, creation tags survive.
    added = {"sim2real:phase": "tagging", "sim2real:keep": "yes"}
    emr.add_tags(
        ResourceId=studio_id,
        Tags=[{"Key": k, "Value": v} for k, v in added.items()],
    )
    after_add = _poll(
        _studio_tags,
        lambda t: all(t.get(k) == v for k, v in added.items()),
        timeout_s=120,
        interval_s=5,
        description=f"AddTags on {studio_id} becomes visible to DescribeStudio",
    )
    for key, value in added.items():
        assert after_add.get(key) == value, (
            f"AddTags must persist {key!r}={value!r}, got {after_add!r}"
        )
    for tag in MANAGED_TAGS:
        assert after_add.get(tag["Key"]) == tag["Value"], (
            f"AddTags must not disturb existing tags; {tag!r} lost from {after_add!r}"
        )

    # --- RemoveTags: exactly the named key goes, and nothing else.
    emr.remove_tags(ResourceId=studio_id, TagKeys=["sim2real:phase"])
    after_remove = _poll(
        _studio_tags,
        lambda t: "sim2real:phase" not in t,
        timeout_s=120,
        interval_s=5,
        description=f"RemoveTags on {studio_id} becomes visible to DescribeStudio",
    )
    assert "sim2real:phase" not in after_remove, (
        f"RemoveTags must delete the named key, got {after_remove!r}"
    )
    assert after_remove.get("sim2real:keep") == "yes", (
        f"RemoveTags must remove ONLY the named key; sim2real:keep was collaterally "
        f"cleared from {after_remove!r}"
    )
    for tag in MANAGED_TAGS:
        assert after_remove.get(tag["Key"]) == tag["Value"], (
            f"RemoveTags must not disturb unnamed keys; {tag!r} lost from "
            f"{after_remove!r}"
        )

    # --- UpdateStudio: the mutable field changes, identity and network do not.
    new_description = "sim2real behavioral studio, updated description"
    emr.update_studio(StudioId=studio_id, Description=new_description)
    updated = _poll(
        lambda: emr.describe_studio(StudioId=studio_id)["Studio"],
        lambda s: s.get("Description") == new_description,
        timeout_s=120,
        interval_s=5,
        description=f"UpdateStudio on {studio_id} becomes visible",
    )
    assert updated["Description"] == new_description, (
        f"UpdateStudio must change the Description, got {updated.get('Description')!r}"
    )
    assert updated["StudioId"] == studio_id, "UpdateStudio must not re-identify the studio"
    assert updated["StudioArn"] == arn, (
        f"UpdateStudio must not change the StudioArn: {arn!r} -> "
        f"{updated['StudioArn']!r}"
    )
    assert updated["VpcId"] == net["vpc"] and updated["SubnetIds"] == [net["subnet"]], (
        f"a Description-only UpdateStudio must not alter the network, got "
        f"{updated['VpcId']!r} / {updated['SubnetIds']!r}"
    )
    assert updated["CreationTime"] == studio["CreationTime"], (
        f"UpdateStudio must not rewrite CreationTime: {studio['CreationTime']!r} -> "
        f"{updated['CreationTime']!r}"
    )
    assert {t["Key"] for t in updated.get("Tags", [])} == set(after_remove), (
        f"a Description-only UpdateStudio must not alter tags: {after_remove!r} -> "
        f"{updated.get('Tags')!r}"
    )

    # --- ListStudios: the summary view agrees with the detail view.
    summaries = {}
    marker = None
    for _ in range(50):
        kwargs = {"Marker": marker} if marker else {}
        resp = emr.list_studios(**kwargs)
        summaries.update({s["StudioId"]: s for s in resp.get("Studios", [])})
        marker = resp.get("Marker")
        if not marker:
            break
    else:
        raise AssertionError("ListStudios did not terminate in 50 pages")
    summary = summaries.get(studio_id)
    assert summary is not None, (
        f"the created studio must appear in ListStudios; saw {sorted(summaries)!r}"
    )
    assert summary["Name"] == studio_name, f"ListStudios Name disagrees: {summary!r}"
    assert summary["VpcId"] == net["vpc"], f"ListStudios VpcId disagrees: {summary!r}"
    assert summary["AuthMode"] == "IAM", f"ListStudios AuthMode disagrees: {summary!r}"
    assert summary["Description"] == new_description, (
        f"ListStudios must reflect the update, got {summary!r}"
    )
    assert summary["CreationTime"] == studio["CreationTime"], (
        f"ListStudios and DescribeStudio must agree on CreationTime: {summary!r}"
    )

    # --- DeleteStudio: the studio really goes.
    emr.delete_studio(StudioId=studio_id)
    created.clear()  # the registered teardown has nothing left to do

    code, message = _poll(
        lambda: _error(lambda: emr.describe_studio(StudioId=studio_id)),
        lambda pair: bool(pair[0]),
        timeout_s=180,
        interval_s=10,
        description=f"DescribeStudio on deleted {studio_id} starts rejecting",
    )
    assert code == "InvalidRequestException", (
        f"DescribeStudio on a deleted studio must reject, got {code!r}"
    )
    expected = _service_message("Studio does not exist.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    remaining = {}
    marker = None
    for _ in range(50):
        kwargs = {"Marker": marker} if marker else {}
        resp = emr.list_studios(**kwargs)
        remaining.update({s["StudioId"]: s for s in resp.get("Studios", [])})
        marker = resp.get("Marker")
        if not marker:
            break
    assert studio_id not in remaining, (
        f"a deleted studio must disappear from ListStudios, {studio_id} is still there"
    )

    # --- a mutation on the dead id fails too, not just a read.
    code, message = _error(
        lambda: emr.update_studio(StudioId=studio_id, Description="post-delete mutation")
    )
    assert code == "InvalidRequestException", (
        f"UpdateStudio on a deleted studio must reject, got {code!r}"
    )
    expected = _service_message("Studio does not exist.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes: resources in the VPC
# delete asynchronously, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with
# DependencyViolation. Wait (bounded) for the ENIs, retry DependencyViolation in the same window,
# and raise naming the ENIs still attached. Teardown-only; the window is shared by all network
# deletes of one check.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
