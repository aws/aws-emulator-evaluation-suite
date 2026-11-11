"""vpc-egress-connector-path-is-blocked-by-the-target-security-group."""
from __future__ import annotations

import base64
import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-egress-connector-path-is-blocked-by-the-target-security-group"
GROUP = "connector-egress-blocked"
SERVICES = ["lambda-core", "lambda-microvms"]

# create -> ACTIVE takes ~250 s.
_ACTIVE_WAIT_S = 600.0
_IMAGE_WAIT_S = 600.0
_RUNNING_WAIT_S = 240.0
_GONE_WAIT_S = 300.0
_ENDPOINT_WAIT_S = 300.0
_ROLE_PROPAGATION_WAIT_S = 180.0
# How long a security-group change is given to become effective on the connector's path, and how
# long the blocked state is held still before it is believed.
_RULE_EFFECTIVE_WAIT_S = 180.0
_BLOCKED_HOLD_SAMPLES = 3
_MICROVM_MAX_AGE_S = 900
_GUEST_CONNECT_TIMEOUT_S = 8

_VPC_CIDR = "10.91.0.0/16"
_SUBNET_CIDR = "10.91.1.0/24"
_TARGET_PORT = 443

_TRUST_LAMBDA = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
_NOT_PROPAGATED = "invalid ConnectorOperatorRole permissions"
_NOT_ASSUMABLE_YET = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)

# The guest: a JSON service on 8080 whose /connect opens one outbound TCP connection and reports
# the socket's view. `outcome` is normalised in the guest because the exception name varies by
# Python version.
_GUEST_SERVER = """
import errno, json, socket, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

TIMEOUT = {timeout}

UNREACHABLE = {{errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN}}


def classify(exc):
    if isinstance(exc, socket.timeout) or isinstance(exc, TimeoutError):
        return "timed_out"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, OSError) and exc.errno in UNREACHABLE:
        return "unreachable"
    return "error:" + type(exc).__name__


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(url.query)
        if url.path == "/health":
            body = {{"healthy": True}}
        elif url.path == "/connect":
            host = query.get("host", [""])[0]
            port = int(query.get("port", ["443"])[0])
            sock = None
            try:
                sock = socket.create_connection((host, port), timeout=TIMEOUT)
                body = {{"connected": True, "outcome": "connected",
                        "peer": list(sock.getpeername()),
                        "local": list(sock.getsockname())}}
            except Exception as exc:
                body = {{"connected": False, "outcome": classify(exc),
                        "detail": str(exc)[:200]}}
            finally:
                if sock is not None:
                    sock.close()
        else:
            body = {{"error": "no such path"}}
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


HTTPServer(("0.0.0.0", 8080), H).serve_forever()
"""


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A private target admitting 443 only from the connector's security group is unreachable from
    the attached MicroVM until that rule exists, reachable while it does, and unreachable again
    once it is revoked; a blocked connect times out because a security group drops silently.
    """
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    mvm = ctx.client("lambda-microvms")
    account = ctx.client("sts").get_caller_identity()["Account"]

    label = ctx.unique_name("sim2real-lncsg-")

    # Two groups, so the arbiter is a rule about the connector's group, not a CIDR.
    vpc_id, subnet_id, zone = _private_network(ctx, ec2, label)
    connector_group = _security_group(ctx, ec2, vpc_id, f"{label}-c", "connector egress")
    target_group = _security_group(ctx, ec2, vpc_id, f"{label}-t", "private target")
    target_ip, endpoint_id = _private_endpoint(
        ctx, ec2, vpc_id, subnet_id, target_group, label
    )
    assert _network_part(target_ip, _VPC_CIDR) == _network_part(
        _VPC_CIDR.split("/")[0], _VPC_CIDR
    ), (
        f"the private target {target_ip!r} is not inside the created VPC CIDR {_VPC_CIDR!r}; the "
        "reachability claims below would not be attributable to this VPC"
    )
    opened = _ingress_sources(ec2, target_group)
    assert opened == [], (
        f"the freshly created target security group already admits {opened!r}; the blocked arm "
        "below must start from a group that admits nothing"
    )

    operator = _operator_role(ctx, iam, label)
    assert operator.startswith(f"arn:aws:iam::{account}:role/"), (
        f"operator role {operator!r} is not an IAM role in the caller account {account!r}"
    )
    created = _create_connector(
        lc,
        Name=label,
        Configuration={
            "VpcEgressConfiguration": {
                "SubnetIds": [subnet_id],
                "SecurityGroupIds": [connector_group],
                "NetworkProtocol": "IPv4",
                "AssociatedComputeResourceTypes": ["MicroVm"],
            }
        },
        OperatorRole=operator,
        Tags={"sim2real": label},
    )
    connector_id = created["Id"]
    connector_arn = created["Arn"]
    ctx.on_cleanup(lambda: _best_effort_delete_connector(lc, connector_id))

    image_arn = _build_guest_image(ctx, mvm, label, account)

    settled = _wait_until(
        lambda: lc.get_network_connector(Identifier=connector_id),
        lambda r: r["State"] in ("ACTIVE", "FAILED"),
        _ACTIVE_WAIT_S,
        15.0,
        "the connector to leave PENDING",
    )
    assert settled["State"] == "ACTIVE", (
        f"the connector settled as {settled['State']!r}, expected 'ACTIVE' "
        f"(code={settled.get('StateReasonCode')} reason={settled.get('StateReason')})"
    )
    stored = settled["Configuration"]["VpcEgressConfiguration"]["SecurityGroupIds"]
    assert stored == [connector_group], (
        f"the ACTIVE connector reports SecurityGroupIds {stored!r}, expected exactly "
        f"[{connector_group!r}] -- the rest of this check is about whether that group is live on "
        "the path, so it has to be the group the service says it is using"
    )

    microvm = _run_microvm(
        ctx, mvm, image_arn, _managed_connector(ctx, "HTTP_INGRESS"), connector_arn
    )

    # No rule: sampled repeatedly so "blocked" is a state, not a slow start.
    for attempt in range(_BLOCKED_HOLD_SAMPLES):
        blocked = _guest_connect(ctx, mvm, microvm, target_ip)
        assert blocked["connected"] is False, (
            f"attempt {attempt + 1} reached {target_ip}:{_TARGET_PORT} from "
            f"{blocked.get('local')!r} while the target security group {target_group!r} admitted "
            "nothing at all -- the connector's path is not subject to the destination's security "
            "group, so SecurityGroupIds is being stored rather than applied"
        )
        assert blocked["outcome"] == "timed_out", (
            f"the blocked connect ended as {blocked['outcome']!r} "
            f"({blocked.get('detail')!r}); a security group DROPS, so real AWS exhausts the "
            "connect budget rather than answering with an RST"
        )

    # Admit exactly the connector's group.
    ec2.authorize_security_group_ingress(
        GroupId=target_group,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": _TARGET_PORT,
                "ToPort": _TARGET_PORT,
                "UserIdGroupPairs": [{"GroupId": connector_group}],
            }
        ],
    )
    admitted = _ingress_sources(ec2, target_group)
    assert admitted == [connector_group], (
        f"after the authorize the target group admits {admitted!r}, expected exactly "
        f"[{connector_group!r}]"
    )
    reached = _wait_until(
        lambda: _guest_connect(ctx, mvm, microvm, target_ip),
        lambda r: r["connected"] is True,
        _RULE_EFFECTIVE_WAIT_S,
        5.0,
        "the authorized rule to open the connector's path",
    )
    assert reached["peer"][0] == target_ip, (
        f"the guest's socket reports peer {reached['peer']!r}, expected the endpoint ENI address "
        f"{target_ip!r} in subnet {subnet_id!r} ({zone})"
    )

    # Revoking the same rule is what makes the group the cause rather than a warm-up.
    ec2.revoke_security_group_ingress(
        GroupId=target_group,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": _TARGET_PORT,
                "ToPort": _TARGET_PORT,
                "UserIdGroupPairs": [{"GroupId": connector_group}],
            }
        ],
    )
    assert _ingress_sources(ec2, target_group) == [], (
        "the revoke did not remove the rule, so the arm below would prove nothing"
    )
    closed = _wait_until(
        lambda: _guest_connect(ctx, mvm, microvm, target_ip),
        lambda r: r["connected"] is False,
        _RULE_EFFECTIVE_WAIT_S,
        5.0,
        "the revoked rule to close the connector's path again",
    )
    assert closed["outcome"] == "timed_out", (
        f"after the revoke the connect ended as {closed['outcome']!r} "
        f"({closed.get('detail')!r}); withdrawing the rule returns the path to the same silent "
        "drop it started in"
    )
    assert _guest_get(ctx, mvm, microvm, "/health")["healthy"] is True, (
        "the guest stopped answering /health, so the closed path is not evidence about the "
        "security group"
    )

    # Teardown in the body: deleting the connector, endpoint and VPC outlasts the 60 s
    # cleanup budget; the MicroVMs also self-terminate at maximumDurationInSeconds.
    _terminate(mvm, microvm["id"])
    _delete_connector_and_prove_gone(lc, connector_id, label)
    _delete_endpoint_and_wait(ec2, endpoint_id)


def _network_part(address: str, cidr: str):
    """The octets of *address* that *cidr*'s prefix length covers, as a list of ints, so the
    caller compares values rather than trusting a bool."""
    keep = int(cidr.split("/")[1]) // 8
    try:
        octets = [int(o) for o in address.split(".")]
    except ValueError:
        return ["unparseable", address]
    if len(octets) != 4:
        return ["unparseable", address]
    return octets[:keep]


def _wait_until(probe, predicate, deadline_s, interval_s, what):
    """Bounded retry. RAISES on timeout -- never returns its last value."""
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"waited {deadline_s}s for {what} and it never happened (last={last!r})"
    )


def _ingress_sources(ec2, group_id):
    """Every source a group admits, flattened and sorted: group ids and CIDRs together."""
    groups = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    sources = []
    for permission in groups[0]["IpPermissions"]:
        sources.extend(pair["GroupId"] for pair in permission.get("UserIdGroupPairs", []))
        sources.extend(rng["CidrIp"] for rng in permission.get("IpRanges", []))
        sources.extend(rng["CidrIpv6"] for rng in permission.get("Ipv6Ranges", []))
    return sorted(sources)


def _private_network(ctx, ec2, label):
    """A VPC and one subnet in a derived AZ."""
    spec = [{"Key": "sim2real", "Value": label}, {"Key": "sim2real-origin", "Value": CHECK}]
    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _swallow_absent(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    # The AZ is derived: the endpoint service is not offered in every zone, and a literal zone
    # name is a different physical zone in the next account.
    offered = {
        z
        for d in ec2.describe_vpc_endpoint_services(
            Filters=[{"Name": "service-name", "Values": [_endpoint_service(ctx)]}]
        )["ServiceDetails"]
        for z in d["AvailabilityZones"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, (
        f"no available AZ in {ctx.region} offers {_endpoint_service(ctx)!r}; "
        f"offered={sorted(offered)!r}"
    )
    zone = usable[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=_SUBNET_CIDR,
        AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": spec}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _swallow_absent(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return vpc_id, subnet_id, zone


def _security_group(ctx, ec2, vpc_id, name, purpose):
    group_id = ec2.create_security_group(
        GroupName=name,
        Description=f"sim2real lambda-core {purpose}",
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "security-group",
                "Tags": [
                    {"Key": "sim2real", "Value": name},
                    {"Key": "sim2real-origin", "Value": CHECK},
                ],
            }
        ],
    )["GroupId"]
    ctx.on_cleanup(
        lambda: _swallow_absent(lambda: ec2.delete_security_group(GroupId=group_id))
    )
    return group_id


def _endpoint_service(ctx) -> str:
    return f"com.amazonaws.{ctx.region}.lambda"


def _private_endpoint(ctx, ec2, vpc_id, subnet_id, group_id, label):
    """One interface VPC endpoint, the only listener in the VPC, so a connection to its private
    address can only arrive through the connector. Private DNS is off; the guest uses the IP."""
    endpoint_id = ec2.create_vpc_endpoint(
        VpcEndpointType="Interface",
        VpcId=vpc_id,
        ServiceName=_endpoint_service(ctx),
        SubnetIds=[subnet_id],
        SecurityGroupIds=[group_id],
        PrivateDnsEnabled=False,
        TagSpecifications=[
            {
                "ResourceType": "vpc-endpoint",
                "Tags": [
                    {"Key": "sim2real", "Value": label},
                    {"Key": "sim2real-origin", "Value": CHECK},
                ],
            }
        ],
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(
        lambda: _swallow_absent(
            lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id])
        )
    )
    ready = _wait_until(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0],
        lambda e: e["State"] in ("available", "failed", "rejected")
        and e.get("NetworkInterfaceIds"),
        _ENDPOINT_WAIT_S,
        10.0,
        "the interface endpoint to settle with an ENI",
    )
    assert ready["State"] == "available", (
        f"the private target endpoint settled as {ready['State']!r}, expected 'available'"
    )
    enis = ec2.describe_network_interfaces(
        NetworkInterfaceIds=ready["NetworkInterfaceIds"]
    )["NetworkInterfaces"]
    addresses = sorted(e["PrivateIpAddress"] for e in enis)
    assert len(addresses) == 1, (
        f"the endpoint provisioned {len(addresses)} ENIs {addresses!r} for one subnet; the target "
        "address must be unambiguous"
    )
    return addresses[0], endpoint_id


def _operator_role(ctx, iam, name):
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_LAMBDA),
        Tags=[{"Key": "sim2real", "Value": name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow_absent(lambda: iam.delete_role(RoleName=name)))
    iam.attach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY)
    ctx.on_cleanup(
        lambda: _swallow_absent(
            lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY)
        )
    )
    return arn


def _create_connector(lc, **kwargs):
    """CreateNetworkConnector, retrying only the two IAM-propagation rejections; IAM exposes no
    condition reporting that a role has become usable."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message", "")
            if (
                _NOT_PROPAGATED not in message and _NOT_ASSUMABLE_YET not in message
            ) or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _managed_connector(ctx, name: str) -> str:
    return f"arn:aws:lambda:{ctx.region}:aws:network-connector:aws-network-connector:{name}"


def _build_guest_image(ctx, mvm, label, account):
    """Build one MicroVM image whose guest reports on its own outbound connectivity.

    The build role is created here, trusted by lambda.amazonaws.com and granted read on the
    throwaway artifact bucket by an inline policy, so the build depends on nothing the account
    already holds.
    """
    bucket = label
    s3 = ctx.client("s3")
    role = _build_role(ctx, ctx.client("iam"), f"{label}-build"[:64], bucket, account)

    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: _swallow_absent(lambda: _empty_and_delete_bucket(s3, bucket)))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-origin", "Value": CHECK}]}
    )

    # base64 rather than a heredoc: a Dockerfile instruction is one logical line, and the guest
    # source contains both newlines and quotes.
    payload = base64.b64encode(
        _GUEST_SERVER.format(timeout=_GUEST_CONNECT_TIMEOUT_S).encode()
    ).decode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "Dockerfile",
            "FROM public.ecr.aws/amazonlinux/amazonlinux:2023\n"
            "RUN dnf install -y python3 && dnf clean all\n"
            "RUN mkdir -p /srv\n"
            f"RUN echo {payload} | base64 -d > /srv/server.py\n"
            'CMD ["/bin/sh","-c","python3 /srv/server.py"]\n',
        )
    s3.put_object(Bucket=bucket, Key="code.zip", Body=buf.getvalue())

    created = _create_image(
        mvm,
        name=label,
        baseImageArn=_managed_base_image(mvm),
        buildRoleArn=role,
        codeArtifact={"uri": f"s3://{bucket}/code.zip"},
        tags={"sim2real-origin": CHECK},
    )
    image_arn = created["imageArn"]
    version = created["imageVersion"]
    ctx.on_cleanup(
        lambda: _swallow_absent(lambda: mvm.delete_microvm_image(imageIdentifier=image_arn))
    )

    settled = _wait_until(
        lambda: mvm.get_microvm_image(imageIdentifier=image_arn),
        lambda i: i["state"] in ("CREATED", "CREATE_FAILED"),
        _IMAGE_WAIT_S,
        10.0,
        "the guest image build to settle",
    )
    built = mvm.get_microvm_image_version(imageIdentifier=image_arn, imageVersion=version)
    assert settled["state"] == "CREATED" and built["state"] == "SUCCESSFUL", (
        f"the guest image build did not succeed: image {settled['state']!r}, version "
        f"{built['state']!r}, reason {built.get('stateReason')!r}"
    )
    return image_arn


_BUILD_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": ["sts:AssumeRole", "sts:TagSession"],
        }
    ],
}
_BUILD_POLICY_NAME = "sim2real-mvm-build"


def _build_role(ctx, iam, name, bucket, account):
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_BUILD_TRUST),
        Tags=[{"Key": "sim2real-origin", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow_absent(lambda: iam.delete_role(RoleName=name)))
    iam.put_role_policy(
        RoleName=name,
        PolicyName=_BUILD_POLICY_NAME,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:GetObjectVersion"],
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:ListBucket"],
                        "Resource": f"arn:aws:s3:::{bucket}",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": f"arn:aws:logs:{ctx.region}:{account}:*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _swallow_absent(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName=_BUILD_POLICY_NAME)
        )
    )
    return arn


def _create_image(mvm, **kwargs):
    """CreateMicrovmImage, retrying only while the fresh build role is not yet visible to the
    service. IAM exposes no readiness condition, so this bounded retry is the wait."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return mvm.create_microvm_image(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("AccessDeniedException", "ResourceNotFoundException") or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(5)


def _managed_base_image(mvm) -> str:
    arns = []
    token = None
    while True:
        page = mvm.list_managed_microvm_images(**({"nextToken": token} if token else {}))
        items = page["items"]
        arns.extend(i["imageArn"] for i in items)
        token = page.get("nextToken")
        if not token or not items:
            break
    assert arns, "ListManagedMicrovmImages returned no managed base image to build from"
    return sorted(arns)[0]


def _run_microvm(ctx, mvm, image_arn, ingress, egress):
    started = mvm.run_microvm(
        imageIdentifier=image_arn,
        maximumDurationInSeconds=_MICROVM_MAX_AGE_S,
        ingressNetworkConnectors=[ingress],
        egressNetworkConnectors=[egress],
    )
    microvm_id = started["microvmId"]
    ctx.on_cleanup(lambda: _terminate(mvm, microvm_id))
    assert started.get("egressNetworkConnectors") == [egress], (
        f"RunMicrovm echoed egressNetworkConnectors "
        f"{started.get('egressNetworkConnectors')!r}, expected exactly [{egress!r}]"
    )
    running = _wait_until(
        lambda: mvm.get_microvm(microvmIdentifier=microvm_id),
        lambda m: m["state"] in ("RUNNING", "FAILED", "TERMINATED"),
        _RUNNING_WAIT_S,
        5.0,
        f"microvm {microvm_id} to leave PENDING",
    )
    assert running["state"] == "RUNNING", (
        f"microvm {microvm_id} settled as {running['state']!r}, expected 'RUNNING' "
        f"(reason={running.get('stateReason')!r})"
    )
    return {"id": microvm_id, "endpoint": started["endpoint"]}


def _guest_token(mvm, microvm_id) -> str:
    token = mvm.create_microvm_auth_token(
        microvmIdentifier=microvm_id,
        expirationInMinutes=15,
        allowedPorts=[{"allPorts": {}}],
    )["authToken"]
    return token["X-aws-proxy-auth"]


def _guest_get(ctx, mvm, microvm, path, retry_budget=180.0):
    """GET *path* on the guest through the MicroVM proxy endpoint and parse its JSON.

    The retry is bounded and waits only for the guest process to start listening; an HTTP response
    of any status ends it, so a 403 from the proxy is reported rather than retried.
    """
    url = f"{ctx.endpoint_url(microvm['endpoint'])}{path}"
    headers = {"X-aws-proxy-auth": _guest_token(mvm, microvm["id"])}
    deadline = time.monotonic() + retry_budget
    while True:
        try:
            request = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(request, timeout=60) as response:
                status, raw = response.status, response.read()
            break
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
            break
        except OSError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"the guest on {microvm['id']} never answered {path!r}: {exc!r}"
                ) from exc
            time.sleep(5)
    assert status == 200, (
        f"GET {path!r} on microvm {microvm['id']} answered HTTP {status}: {raw[:200]!r}"
    )
    return json.loads(raw.decode())


def _guest_connect(ctx, mvm, microvm, target_ip):
    query = urllib.parse.urlencode({"host": target_ip, "port": _TARGET_PORT})
    return _guest_get(ctx, mvm, microvm, f"/connect?{query}")


def _terminate(mvm, microvm_id):
    try:
        mvm.terminate_microvm(microvmIdentifier=microvm_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_connector_and_prove_gone(lc, connector_id, name):
    deleted = lc.delete_network_connector(Identifier=connector_id)
    assert deleted["Id"] == connector_id, (
        f"Delete echoed Id {deleted['Id']!r}, expected {connector_id!r}"
    )
    assert deleted["State"] == "DELETING", (
        f"Delete reported State {deleted['State']!r}, expected 'DELETING'"
    )
    _wait_until(
        lambda: _get_or_gone(lc, connector_id),
        lambda v: v == "GONE",
        _GONE_WAIT_S,
        10.0,
        "the deleted connector to stop answering Get",
    )
    code, message = _error(lambda: lc.get_network_connector(Identifier=name))
    assert code == "ResourceNotFoundException", (
        f"the deleted connector is still resolvable by name {name!r} ({code!r})"
    )
    expected = f"Network connector not found: {name}"
    assert message == expected, (
        f"Get by name of the deleted connector said {message!r}, expected {expected!r}"
    )


def _get_or_gone(lc, connector_id):
    try:
        return lc.get_network_connector(Identifier=connector_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return "GONE"
        raise


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; a success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


def _delete_endpoint_and_wait(ec2, endpoint_id):
    """Delete the endpoint and wait for its ENI to go; the security groups and subnet cannot be
    deleted while the ENI holds them."""
    ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id])
    _wait_until(
        lambda: ec2.describe_vpc_endpoints(
            Filters=[{"Name": "vpc-endpoint-id", "Values": [endpoint_id]}]
        )["VpcEndpoints"],
        lambda found: not found or found[0]["State"] == "deleted",
        _ENDPOINT_WAIT_S,
        10.0,
        "the interface endpoint and its ENI to disappear",
    )


def _best_effort_delete_connector(lc, connector_id):
    """Safety net for the failure path; the body deletes the connector and proves it gone."""
    try:
        lc.delete_network_connector(Identifier=connector_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return


def _empty_and_delete_bucket(s3, bucket):
    token = None
    while True:
        page = s3.list_objects_v2(
            Bucket=bucket, **({"ContinuationToken": token} if token else {})
        )
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        token = page.get("NextContinuationToken")
        if not token:
            break
    s3.delete_bucket(Bucket=bucket)


def _swallow_absent(fn):
    """Run a teardown net that the body has probably already done. Absence is success; anything
    else is re-raised, so a cleanup that genuinely could not delete is reported."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code") or ""
        if code in (
            "ResourceNotFoundException",
            "NoSuchBucket",
            "NoSuchEntity",
            "InvalidVpcID.NotFound",
            "InvalidSubnetID.NotFound",
            "InvalidGroup.NotFound",
            "InvalidVpcEndpointId.NotFound",
        ):
            return
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
