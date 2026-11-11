"""microvm-denied-the-vpc-egress-connector-cannot-reach-the-private-subnet."""
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

CHECK = "microvm-denied-the-vpc-egress-connector-cannot-reach-the-private-subnet"
GROUP = "connector-egress-denied"
SERVICES = ["lambda-core", "lambda-microvms"]

# create -> ACTIVE takes ~250 s.
_ACTIVE_WAIT_S = 600.0
_IMAGE_WAIT_S = 600.0
_RUNNING_WAIT_S = 240.0
_GONE_WAIT_S = 300.0
_ENDPOINT_WAIT_S = 300.0
_ROLE_PROPAGATION_WAIT_S = 180.0
# The MicroVM self-terminates at this age even if teardown never runs.
_MICROVM_MAX_AGE_S = 900
# The guest's own connect budget. Long enough that a reachable target always answers, short
# enough that the unreachable arm reports inside one HTTP request.
_GUEST_CONNECT_TIMEOUT_S = 8

_VPC_CIDR = "10.90.0.0/16"
_SUBNET_CIDR = "10.90.1.0/24"
_TARGET_PORT = 443
# The guest's own source address through the connector is link-local (169.254.0.2), never a
# customer-subnet address: the connector's ENI is a translating hop.
_GUEST_LINK_LOCAL_CIDR = "169.254.0.0/16"

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
# The two IAM-propagation rejections of a freshly created operator role.
_NOT_PROPAGATED = "invalid ConnectorOperatorRole permissions"
_NOT_ASSUMABLE_YET = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)

# The guest: a JSON service on 8080 whose /connect opens one outbound TCP connection and reports
# the socket's view (`local` is the source address the egress path gave it). `outcome` is
# normalised in the guest because the exception name varies by Python version.
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
    """A MicroVM attached to the VPC_EGRESS connector reaches a private endpoint in its subnet from a
    link-local source, while an identical MicroVM on INTERNET_EGRESS only times out connecting.
    """
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    mvm = ctx.client("lambda-microvms")
    account = ctx.client("sts").get_caller_identity()["Account"]

    label = ctx.unique_name("sim2real-lncdp-")

    vpc_id, subnet_id, zone, group_id = _private_network(ctx, ec2, label)
    target_ip, endpoint_id = _private_endpoint(ctx, ec2, vpc_id, subnet_id, group_id, label)
    assert _network_part(target_ip, _VPC_CIDR) == _network_part(
        _VPC_CIDR.split("/")[0], _VPC_CIDR
    ), (
        f"the private target {target_ip!r} is not inside the created VPC CIDR {_VPC_CIDR!r}; "
        "the reachability claim below would not be attributable to the connector"
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
                "SecurityGroupIds": [group_id],
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

    # One image, built while the connector provisions, so both MicroVMs are identical.
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

    # Two MicroVMs differing only in egressNetworkConnectors.
    internet_egress = _managed_connector(ctx, "INTERNET_EGRESS")
    http_ingress = _managed_connector(ctx, "HTTP_INGRESS")
    denied = _run_microvm(ctx, mvm, image_arn, http_ingress, internet_egress)
    connected = _run_microvm(ctx, mvm, image_arn, http_ingress, connector_arn)
    assert connected["egress"] == [connector_arn], (
        f"RunMicrovm echoed egressNetworkConnectors {connected['egress']!r}, expected exactly "
        f"[{connector_arn!r}] -- the treatment MicroVM is not attached to the connector under test"
    )
    assert denied["egress"] == [internet_egress], (
        f"RunMicrovm echoed egressNetworkConnectors {denied['egress']!r} for the control "
        f"MicroVM, expected exactly [{internet_egress!r}]"
    )

    reached = _guest_connect(ctx, mvm, connected, target_ip)
    assert reached["connected"] is True, (
        f"the MicroVM attached to the ACTIVE VPC_EGRESS connector could not reach "
        f"{target_ip}:{_TARGET_PORT} inside its own subnet {subnet_id!r} "
        f"({reached.get('outcome')}: {reached.get('detail')!r}) -- the connector reports ACTIVE, "
        "so the network path it exists to provide is missing"
    )
    assert reached["peer"][0] == target_ip, (
        f"the guest's socket reports peer {reached['peer']!r}, expected the endpoint ENI address "
        f"{target_ip!r}"
    )
    # The connector translates, so the guest's source is link-local, not a subnet address.
    source_ip = reached["local"][0]
    assert _network_part(source_ip, _GUEST_LINK_LOCAL_CIDR) == _network_part(
        _GUEST_LINK_LOCAL_CIDR.split("/")[0], _GUEST_LINK_LOCAL_CIDR
    ), (
        f"the guest reached the target from source address {source_ip!r}, which is outside "
        f"{_GUEST_LINK_LOCAL_CIDR!r}; real AWS hands the guest a link-local address and the "
        f"connector translates on its way into subnet {subnet_id!r} ({zone})"
    )
    assert _network_part(source_ip, _SUBNET_CIDR) != _network_part(
        _SUBNET_CIDR.split("/")[0], _SUBNET_CIDR
    ), (
        f"the guest's source address {source_ip!r} is inside the connector's own subnet CIDR "
        f"{_SUBNET_CIDR!r}; real AWS never gives the guest an address in the customer subnet -- "
        "the connector's ENI is the translating hop, not an interface the guest holds"
    )

    # No path into the VPC means nothing sends an RST, so the connect times out.
    refused = _guest_connect(ctx, mvm, denied, target_ip)
    assert refused["connected"] is False, (
        f"the MicroVM attached only to {internet_egress!r} reached {target_ip}:{_TARGET_PORT} "
        f"from source {refused.get('local')!r} -- a private address inside a VPC it has no "
        "connector for must be unreachable, so egressNetworkConnectors is being stored rather "
        "than enforced as a network path"
    )
    assert refused["outcome"] == "timed_out", (
        f"the denied connect ended as {refused['outcome']!r} ({refused.get('detail')!r}); real "
        "AWS exhausts the connect budget, because with no path into the VPC there is nothing to "
        "answer with an RST"
    )
    assert "local" not in refused, (
        f"the denied attempt still reported a local address {refused.get('local')!r}; a socket "
        "that never connected has no source address on the path"
    )

    # The denied guest is still alive, so the denial is about the VPC path.
    assert _guest_get(ctx, mvm, denied, "/health")["healthy"] is True, (
        "the denied MicroVM's guest stopped answering /health, so its failure to reach the "
        "private address is not evidence about the connector"
    )

    # Teardown in the body: deleting the connector, endpoint and VPC outlasts the 60 s
    # cleanup budget; the MicroVMs also self-terminate at maximumDurationInSeconds.
    _terminate(mvm, denied["id"])
    _terminate(mvm, connected["id"])
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


def _private_network(ctx, ec2, label):
    """A VPC, one subnet in a derived AZ, and a security group that admits the connector's
    traffic on the target port."""
    spec = [{"Key": "sim2real", "Value": label}, {"Key": "sim2real-origin", "Value": CHECK}]
    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _swallow_absent(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    # The AZ is derived: an interface endpoint for the service is not offered in every zone, and
    # a literal zone name is a different physical zone in the next account.
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
        f"no available AZ in {ctx.region} offers {_endpoint_service(ctx)!r}; offered={sorted(offered)!r}"
    )
    zone = usable[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=_SUBNET_CIDR,
        AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": spec}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _swallow_absent(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    group_id = ec2.create_security_group(
        GroupName=label,
        Description="sim2real lambda-core VPC egress connector data plane",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": spec}],
    )["GroupId"]
    ctx.on_cleanup(
        lambda: _swallow_absent(lambda: ec2.delete_security_group(GroupId=group_id))
    )
    # Admit the connector's traffic, scoped to this run's VPC CIDR.
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": _TARGET_PORT,
                "ToPort": _TARGET_PORT,
                "IpRanges": [{"CidrIp": _VPC_CIDR}],
            }
        ],
    )
    return vpc_id, subnet_id, zone, group_id


def _endpoint_service(ctx) -> str:
    return f"com.amazonaws.{ctx.region}.lambda"


def _private_endpoint(ctx, ec2, vpc_id, subnet_id, group_id, label):
    """One interface VPC endpoint, the only listener in the VPC, so a connection to its private
    address can only arrive through the connector. Private DNS is off; the guest uses the IP."""
    endpoint = ec2.create_vpc_endpoint(
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
    )["VpcEndpoint"]
    endpoint_id = endpoint["VpcEndpointId"]
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
        f"the endpoint provisioned {len(addresses)} ENIs {addresses!r} for one subnet; the "
        "target address must be unambiguous"
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
    return (
        f"arn:aws:lambda:{ctx.region}:aws:network-connector:aws-network-connector:{name}"
    )


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
    ctx.on_cleanup(lambda: _swallow_absent(lambda: mvm.delete_microvm_image(imageIdentifier=image_arn)))

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
    return {
        "id": microvm_id,
        "endpoint": started["endpoint"],
        "egress": started.get("egressNetworkConnectors"),
    }


def _guest_token(mvm, microvm_id) -> str:
    token = mvm.create_microvm_auth_token(
        microvmIdentifier=microvm_id,
        expirationInMinutes=15,
        allowedPorts=[{"allPorts": {}}],
    )["authToken"]
    return token["X-aws-proxy-auth"]


def _guest_get(ctx, mvm, microvm, path, retry_budget=180.0):
    """GET *path* on the guest through the MicroVM proxy endpoint and parse its JSON.

    The retry is bounded and waits only for the guest process to start listening; an HTTP
    response of any status ends it, so a 403 from the proxy is reported rather than retried.
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
        f"GET {path!r} on microvm {microvm['id']} answered HTTP {status}: "
        f"{raw[:200]!r}"
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
    """Delete the endpoint and wait for its ENI to go; the security group and subnet cannot be
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
