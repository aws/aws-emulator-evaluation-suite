"""log-vpc-flow-logs-s3-accept-and-rejected-records."""
from __future__ import annotations

import gzip
import random
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-vpc-flow-logs-s3-accept-and-rejected-records"
GROUP = "flow-log-capture"
SERVICES = ["ec2", "s3"]

# The custom format this check configures. Every assertion below decodes a record by THIS order.
FIELDS = [
    "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport",
    "protocol", "packets", "bytes", "start", "end", "action", "log-status", "flow-direction",
]
INTERVAL_S = 60


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html
@tags("cap:c2", "cap:c3", "plane:data", "dp:api", "concern:data-plane",
      "axis:happy-path", "timing:real-time")
def run(ctx) -> None:
    """An S3 flow log on a server ENI records both the SG-accepted (ACCEPT) and SG-blocked (REJECT)
    connections a client caused, field by field, under the plain key layout, and the aggregation
    interval splits one repeating flow into several records.

    Reference: https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
    """
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    scenario = CHECK

    ami = _ami(ec2)
    az = _az(ec2, "t3.micro")
    p_ok, p_block = random.sample(range(20000, 29999), 2)
    sp_ok, sp_block = random.sample(range(40000, 49999), 2)
    t_run_start = int(time.time())

    # registered first so it is emptied and deleted LAST
    bucket = ctx.unique_name("sim2real-fl-a-")
    _create_bucket(ctx, s3, bucket, region)
    prefix = "flowlogs"

    vpc = _vpc(ctx, ec2, "10.81.0.0/16", scenario)
    subnet = _subnet(ctx, ec2, vpc, "10.81.1.0/24", az, scenario)
    sg_client = _sg(ctx, ec2, vpc, ctx.unique_name("sim2real-fl-cli-"), scenario)
    sg_server = _sg(ctx, ec2, vpc, ctx.unique_name("sim2real-fl-srv-"), scenario)
    ec2.authorize_security_group_ingress(
        GroupId=sg_server,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": p_ok, "ToPort": p_ok,
                        "UserIdGroupPairs": [{"GroupId": sg_client}]}],
    )
    eni_client, ip_client = _eni(ctx, ec2, subnet, sg_client, scenario)
    eni_server, ip_server = _eni(ctx, ec2, subnet, sg_server, scenario)

    # the flow log exists BEFORE any packet can flow
    fl = ec2.create_flow_logs(
        ResourceIds=[eni_server], ResourceType="NetworkInterface", TrafficType="ALL",
        LogDestinationType="s3", LogDestination=f"arn:aws:s3:::{bucket}/{prefix}",
        LogFormat=" ".join("${%s}" % f for f in FIELDS), MaxAggregationInterval=INTERVAL_S,
        DestinationOptions={"FileFormat": "plain-text", "HiveCompatiblePartitions": False,
                            "PerHourPartition": False},
        TagSpecifications=_tags("vpc-flow-log", ctx.unique_name("sim2real-fl-"), scenario),
    )
    fl_ids = fl.get("FlowLogIds") or []
    if fl_ids:
        ctx.on_cleanup(lambda: ec2.delete_flow_logs(FlowLogIds=fl_ids))
    assert not fl.get("Unsuccessful") and len(fl_ids) == 1, (
        f"CreateFlowLogs did not create exactly one flow log: {fl!r}"
    )
    fl_id = fl_ids[0]

    _launch(ctx, ec2, ami, [
        (eni_server, _server_userdata([p_ok, p_block])),
        (eni_client, _client_userdata([
            (ip_server, p_ok, sp_ok),
            (ip_server, p_block, sp_block),
        ])),
    ], scenario)

    key_prefix = f"{prefix}/AWSLogs/{account}/vpcflowlogs/{region}/"

    def want(recs):
        acc = [r for r in recs if _is(r, ip_client, ip_server, sp_ok, p_ok)]
        rej = [r for r in recs if _is(r, ip_client, ip_server, sp_block, p_block)]
        return acc and rej and len({r["start"] for r in acc}) >= 2

    files = _poll_s3_records(s3, bucket, prefix + "/", FIELDS, want, budget_s=1200)
    recs = [r for _, _, rs in files for r in rs]
    now = int(time.time())

    # key layout: <prefix>/AWSLogs/<account>/vpcflowlogs/<region>/<yyyy>/<mm>/<dd>/<file>
    key_re = re.compile(
        re.escape(key_prefix) + r"(\d{4})/(\d{2})/(\d{2})/"
        + re.escape(f"{account}_vpcflowlogs_{region}_{fl_id}_") + r"\d{8}T\d{4}Z_[0-9a-f]+\.log\.gz$"
    )
    for key, header, _ in files:
        assert key_re.match(key), f"delivered key {key!r} does not follow {key_re.pattern!r}"
        assert header == FIELDS, f"object {key!r} header is {header!r}, configured {FIELDS!r}"

    # an ENI-scoped flow log carries only that ENI
    ifaces = {r["interface-id"] for r in recs}
    assert ifaces == {eni_server}, f"ENI flow log on {eni_server!r} carried interfaces {ifaces!r}"

    acc = [r for r in recs if _is(r, ip_client, ip_server, sp_ok, p_ok)]
    rej = [r for r in recs if _is(r, ip_client, ip_server, sp_block, p_block)]
    for r in acc:
        assert r["action"] == "ACCEPT", f"SG-allowed flow recorded as {r['action']!r}: {r!r}"
        assert r["protocol"] == "6", f"TCP flow recorded protocol {r['protocol']!r}: {r!r}"
        assert r["flow-direction"] == "ingress", f"inbound flow recorded as {r!r}"
        assert int(r["packets"]) > 0 and int(r["bytes"]) > 0, f"accepted flow empty: {r!r}"
        assert r["log-status"] == "OK", f"captured interval log-status {r['log-status']!r}"
        assert r["account-id"] == account, f"account-id {r['account-id']!r} != {account!r}"
        assert r["version"] == "5", f"custom format with v5 fields reported version {r['version']!r}"
        _in_window(r, t_run_start, now)
    for r in rej:
        assert r["action"] == "REJECT", (
            f"flow to SG-blocked port {p_block} recorded as {r['action']!r}, not REJECT: {r!r}"
        )
        assert r["protocol"] == "6" and int(r["packets"]) > 0, f"blocked flow record {r!r}"
        assert r["log-status"] == "OK", f"captured interval log-status {r['log-status']!r}"
        _in_window(r, t_run_start, now)

    # the aggregation interval is a grouping: one repeating 5-tuple, several records
    starts = sorted({int(r["start"]) for r in acc})
    assert len(starts) >= 2, f"repeating flow collapsed into {len(starts)} record window(s)"
    assert starts[-1] > starts[0], f"record windows did not advance: {starts!r}"


def _is(r, src, dst, sport, dport):
    return (r.get("srcaddr") == src and r.get("dstaddr") == dst
            and r.get("srcport") == str(sport) and r.get("dstport") == str(dport))


def _in_window(r, t0, t1):
    s, e = int(r["start"]), int(r["end"])
    assert t0 - 60 <= s <= e <= t1 + 60, (
        f"record start/end ({s}, {e}) not plausible epoch seconds in run window [{t0}, {t1}]: {r!r}"
    )


def _poll_s3_records(s3, bucket, prefix, fields, want, budget_s):
    """Poll every delivered object under prefix until want(records) holds. Returns
    [(key, header_fields, [record dicts])]. Content is asserted, never latency."""
    seen: dict = {}
    deadline = time.time() + budget_s
    while True:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
            for o in page.get("Contents", []):
                k = o["Key"]
                if k in seen or not k.endswith(".log.gz"):
                    continue
                body = gzip.decompress(s3.get_object(Bucket=bucket, Key=k)["Body"].read())
                lines = [ln for ln in body.decode().splitlines() if ln.strip()]
                header = lines[0].split(" ") if lines else []
                rows = [dict(zip(fields, ln.split(" "))) for ln in lines[1:]]
                for ln in lines[1:]:
                    assert len(ln.split(" ")) == len(fields), f"record {ln!r} in {k!r} has wrong arity"
                seen[k] = (k, header, rows)
        out = list(seen.values())
        if want([r for _, _, rs in out for r in rs]):
            return out
        if time.time() > deadline:
            raise AssertionError(
                f"flow-log records for the caused connections never arrived under "
                f"s3://{bucket}/{prefix} within {budget_s}s; objects seen: {sorted(seen)!r}; "
                f"records: {[r for _, _, rs in out for r in rs][:20]!r}"
            )
        time.sleep(20)


def _tags(kind, name, scenario):
    return [{"ResourceType": kind, "Tags": [{"Key": "Name", "Value": name},
                                            {"Key": "sim2real", "Value": scenario}]}]


def _retry(fn, codes=("DependencyViolation", "InvalidNetworkInterface.InUse"), budget_s=600):
    deadline = time.time() + budget_s
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code.endswith(".NotFound"):
                return None
            if code not in codes or time.time() > deadline:
                raise
            time.sleep(10)


def _ami(ec2):
    imgs = ec2.describe_images(Owners=["amazon"], Filters=[
        {"Name": "name", "Values": ["al2023-ami-2023.*-kernel-6.1-x86_64"]},
        {"Name": "state", "Values": ["available"]}])["Images"]
    assert imgs, "no available Amazon Linux 2023 x86_64 AMI found in this region"
    return max(imgs, key=lambda i: i["CreationDate"])["ImageId"]


def _az(ec2, want):
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [want]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {want!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _create_bucket(ctx, s3, bucket, region):
    kw = {} if region == "us-east-1" else {
        "CreateBucketConfiguration": {"LocationConstraint": region}}
    s3.create_bucket(Bucket=bucket, **kw)

    def _empty_and_delete():
        for _ in range(6):
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
                objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if objs:
                    s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
            try:
                s3.delete_bucket(Bucket=bucket)
                return
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchBucket":
                    return
                if e.response["Error"]["Code"] != "BucketNotEmpty":
                    raise
                time.sleep(10)  # a final delivery landed after the flow log was deleted; re-empty
        s3.delete_bucket(Bucket=bucket)
    ctx.on_cleanup(_empty_and_delete)


def _vpc(ctx, ec2, cidr, scenario):
    vpc = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=_tags(
        "vpc", ctx.unique_name("sim2real-fl-vpc-"), scenario))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry(lambda: ec2.delete_vpc(VpcId=vpc)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc


def _subnet(ctx, ec2, vpc, cidr, az, scenario):
    sn = ec2.create_subnet(VpcId=vpc, CidrBlock=cidr, AvailabilityZone=az, TagSpecifications=_tags(
        "subnet", ctx.unique_name("sim2real-fl-sn-"), scenario))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry(lambda: ec2.delete_subnet(SubnetId=sn)))
    return sn


def _sg(ctx, ec2, vpc, name, scenario):
    sg = ec2.create_security_group(GroupName=name, Description=f"{name} sim2real flow-log check",
                                   VpcId=vpc, TagSpecifications=_tags("security-group", name,
                                                                      scenario))["GroupId"]
    ctx.on_cleanup(lambda: _retry(lambda: ec2.delete_security_group(GroupId=sg)))
    return sg


def _eni(ctx, ec2, subnet, sg, scenario):
    ni = ec2.create_network_interface(
        SubnetId=subnet, Groups=[sg], Description="sim2real flow-log check",
        TagSpecifications=_tags("network-interface", ctx.unique_name("sim2real-fl-eni-"), scenario),
    )["NetworkInterface"]
    eni = ni["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _retry(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni)))
    return eni, ni["PrivateIpAddress"]


def _launch(ctx, ec2, ami, specs, scenario):
    """specs: [(eni_id, user_data)]. ONE teardown net: terminate all, then wait once."""
    ids: list = []

    def _terminate():
        if ids:
            ec2.terminate_instances(InstanceIds=ids)
            ec2.get_waiter("instance_terminated").wait(
                InstanceIds=ids, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(_terminate)
    for eni, ud in specs:
        name = ctx.unique_name("sim2real-fl-i-")
        r = ec2.run_instances(
            ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1, UserData=ud,
            NetworkInterfaces=[{"DeviceIndex": 0, "NetworkInterfaceId": eni}],
            TagSpecifications=_tags("instance", name, scenario) + _tags("volume", name, scenario),
        )
        ids.append(r["Instances"][0]["InstanceId"])
    ec2.get_waiter("instance_running").wait(InstanceIds=list(ids), WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return ids


def _server_userdata(ports):
    return """#!/bin/bash
cat >/root/sim2real_srv.py <<'EOF'
import socket, threading, time
def serve(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(64)
    while True:
        c, _ = s.accept()
        try:
            c.settimeout(5); c.recv(4096); c.sendall(b"sim2real-ack\\n")
        except Exception:
            pass
        finally:
            c.close()
for p in %r:
    threading.Thread(target=serve, args=(p,), daemon=True).start()
while True:
    time.sleep(3600)
EOF
nohup python3 /root/sim2real_srv.py >/dev/null 2>&1 &
""" % (list(ports),)


def _client_userdata(targets):
    """targets: [(dst_ip, dst_port, fixed_src_port)] connected every 10 s for 40 min."""
    return """#!/bin/bash
cat >/root/sim2real_cli.py <<'EOF'
import socket, struct, time
end = time.time() + 2400
while time.time() < end:
    for ip, dp, sp in %r:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.settimeout(3)
        try:
            s.bind(("0.0.0.0", sp)); s.connect((ip, dp))
            s.sendall(b"sim2real-flow-log-probe " * 20); s.recv(64)
        except Exception:
            pass
        finally:
            s.close()
    time.sleep(10)
EOF
nohup python3 /root/sim2real_cli.py >/dev/null 2>&1 &
""" % (list(targets),)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
