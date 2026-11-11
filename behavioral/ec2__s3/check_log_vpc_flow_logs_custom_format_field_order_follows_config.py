"""log-vpc-flow-logs-custom-format-field-order-follows-config."""
from __future__ import annotations

import gzip
import random
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-vpc-flow-logs-custom-format-field-order-follows-config"
GROUP = "flow-log-format"
SERVICES = ["ec2", "s3"]

# Two formats over the SAME field set; the second swaps srcaddr and dstport (an IP and a port),
# so a fixed-layout implementation puts a value of the wrong TYPE in both slots.
FIELDS_A = ["interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
            "action", "packets", "bytes", "start", "end", "log-status"]
FIELDS_B = ["interface-id", "dstport", "dstaddr", "srcport", "srcaddr", "protocol",
            "action", "packets", "bytes", "start", "end", "log-status"]
INTERVAL_S = 60


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html
@tags(
    "cap:c2",
    "cap:c3",
    "plane:data",
    "dp:api",
    "concern:data-plane",
    "concern:representation",
    "axis:happy-path",
    "timing:real-time",
)
def run(ctx) -> None:
    """Two S3 flow logs on one ENI whose LogFormats differ only by swapping srcaddr and dstport
    deliver records whose columns follow each configured order; one uses the plain key layout,
    the other Hive-compatible per-hour partitions.

    Reference: https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3-path.html
    """
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    scenario = CHECK

    ami = _ami(ec2)
    az = _az(ec2, "t3.micro")
    p_ok = random.randrange(20000, 29999)
    sp_ok = random.randrange(40000, 49999)
    t_run_start = int(time.time())

    bucket = ctx.unique_name("sim2real-fl-b-")
    _create_bucket(ctx, s3, bucket, region)

    vpc = _vpc(ctx, ec2, "10.82.0.0/16", scenario)
    subnet = _subnet(ctx, ec2, vpc, "10.82.1.0/24", az, scenario)
    sg_client = _sg(ctx, ec2, vpc, ctx.unique_name("sim2real-fl-cli-"), scenario)
    sg_server = _sg(ctx, ec2, vpc, ctx.unique_name("sim2real-fl-srv-"), scenario)
    ec2.authorize_security_group_ingress(
        GroupId=sg_server,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": p_ok, "ToPort": p_ok,
                        "UserIdGroupPairs": [{"GroupId": sg_client}]}],
    )
    eni_client, ip_client = _eni(ctx, ec2, subnet, sg_client, scenario)
    eni_server, ip_server = _eni(ctx, ec2, subnet, sg_server, scenario)

    ids = {}
    for label, fields, hive in (("a", FIELDS_A, False), ("b", FIELDS_B, True)):
        fl = ec2.create_flow_logs(
            ResourceIds=[eni_server], ResourceType="NetworkInterface", TrafficType="ALL",
            LogDestinationType="s3", LogDestination=f"arn:aws:s3:::{bucket}/fmt-{label}",
            LogFormat=" ".join("${%s}" % f for f in fields), MaxAggregationInterval=INTERVAL_S,
            DestinationOptions={"FileFormat": "plain-text", "HiveCompatiblePartitions": hive,
                                "PerHourPartition": hive},
            TagSpecifications=_tags("vpc-flow-log", ctx.unique_name("sim2real-fl-"), scenario),
        )
        got = fl.get("FlowLogIds") or []
        if got:
            ctx.on_cleanup(lambda got=got: ec2.delete_flow_logs(FlowLogIds=got))
        assert not fl.get("Unsuccessful") and len(got) == 1, (
            f"CreateFlowLogs ({label}) did not create exactly one flow log: {fl!r}"
        )
        ids[label] = got[0]

    _launch(ctx, ec2, ami, [
        (eni_server, _server_userdata([p_ok])),
        (eni_client, _client_userdata([(ip_server, p_ok, sp_ok)])),
    ], scenario)

    def want(recs):
        return any(_is(r, ip_client, ip_server, sp_ok, p_ok) for r in recs)

    files_a = _poll_s3_records(s3, bucket, "fmt-a/", FIELDS_A, want, budget_s=1200)
    files_b = _poll_s3_records(s3, bucket, "fmt-b/", FIELDS_B, want, budget_s=600)
    now = int(time.time())

    # ---- shape is the contract: header line, then column positions, field by field ----
    for key, header, _ in files_a:
        assert header == FIELDS_A, f"log A object {key!r} header {header!r} != {FIELDS_A!r}"
    for key, header, _ in files_b:
        assert header == FIELDS_B, f"log B object {key!r} header {header!r} != {FIELDS_B!r}"

    for label, files, fields in (("A", files_a, FIELDS_A), ("B", files_b, FIELDS_B)):
        hit = [r for _, _, rs in files for r in rs if _is(r, ip_client, ip_server, sp_ok, p_ok)]
        assert hit, f"log {label} lost the caused connection after polling"
        r = hit[0]
        cols = [r[f] for f in fields]  # the record re-serialised in configured order
        expect = {"interface-id": eni_server, "srcaddr": ip_client, "dstaddr": ip_server,
                  "srcport": str(sp_ok), "dstport": str(p_ok), "protocol": "6",
                  "action": "ACCEPT", "log-status": "OK"}
        for i, f in enumerate(fields):
            if f in expect:
                assert cols[i] == expect[f], (
                    f"log {label} column {i} is configured as {f!r}; expected {expect[f]!r}, "
                    f"got {cols[i]!r} in {cols!r}"
                )
        assert int(r["packets"]) > 0 and int(r["bytes"]) > 0, f"log {label} empty flow {r!r}"
        _in_window(r, t_run_start, now)

    # the swap is visible as raw columns: position 1 holds an IP in A and a port in B
    raw_a = [r for _, _, rs in files_a for r in rs if _is(r, ip_client, ip_server, sp_ok, p_ok)][0]
    raw_b = [r for _, _, rs in files_b for r in rs if _is(r, ip_client, ip_server, sp_ok, p_ok)][0]
    col1_a, col1_b = raw_a[FIELDS_A[1]], raw_b[FIELDS_B[1]]
    col4_a, col4_b = raw_a[FIELDS_A[4]], raw_b[FIELDS_B[4]]
    assert (col1_a, col4_a) == (ip_client, str(p_ok)), f"log A cols 1/4 = {(col1_a, col4_a)!r}"
    assert (col1_b, col4_b) == (str(p_ok), ip_client), f"log B cols 1/4 = {(col1_b, col4_b)!r}"

    # ---- delivery layout: plain vs hive-compatible + per-hour partitions ----
    tail = r"\d{8}T\d{4}Z_[0-9a-f]+\.log\.gz$"
    plain = re.compile(
        re.escape(f"fmt-a/AWSLogs/{account}/vpcflowlogs/{region}/") + r"\d{4}/\d{2}/\d{2}/"
        + re.escape(f"{account}_vpcflowlogs_{region}_{ids['a']}_") + tail)
    hive = re.compile(
        re.escape(f"fmt-b/AWSLogs/aws-account-id={account}/aws-service=vpcflowlogs/"
                  f"aws-region={region}/")
        + r"year=\d{4}/month=\d{2}/day=\d{2}/hour=\d{2}/"
        + re.escape(f"{account}_vpcflowlogs_{region}_{ids['b']}_") + tail)
    for key, _, _ in files_a:
        assert plain.match(key), f"plain-layout key {key!r} does not match {plain.pattern!r}"
    for key, _, _ in files_b:
        assert hive.match(key), f"hive-layout key {key!r} does not match {hive.pattern!r}"


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
