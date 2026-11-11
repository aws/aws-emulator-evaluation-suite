"""log-vpc-flow-logs-traffic-type-filter-excludes-other-action."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-vpc-flow-logs-traffic-type-filter-excludes-other-action"
GROUP = "flow-log-filter"
SERVICES = ["ec2", "iam", "logs"]

FIELDS = ["interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
          "packets", "bytes", "start", "end", "action", "log-status"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html
@tags("cap:c2", "cap:c3", "plane:control", "plane:data", "dp:api", "concern:data-plane",
      "concern:negative-classes", "axis:rejection", "timing:real-time")
def run(ctx) -> None:
    """On one ENI, the ALL flow log carries both an allowed and an SG-blocked flow, the ACCEPT log
    only the allowed one and the REJECT log only the blocked one; an unknown LogFormat field is
    refused InvalidParameter and creates no flow log.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    logs = ctx.client("logs")
    ident = ctx.client("sts").get_caller_identity()
    account, partition = ident["Account"], ident["Arn"].split(":")[1]
    region = ctx.region
    scenario = CHECK

    ami = _ami(ec2)
    az = _az(ec2, "t3.micro")
    p_ok, p_block = random.sample(range(20000, 29999), 2)
    sp_ok, sp_block = random.sample(range(40000, 49999), 2)
    t_run_start = int(time.time())

    groups = {t: _log_group(ctx, logs, scenario) for t in ("ALL", "ACCEPT", "REJECT")}
    role = _delivery_role(ctx, iam, account, partition, region, list(groups.values()), scenario)

    vpc = _vpc(ctx, ec2, "10.83.0.0/16", scenario)
    subnet = _subnet(ctx, ec2, vpc, "10.83.1.0/24", az, scenario)
    sg_client = _sg(ctx, ec2, vpc, ctx.unique_name("sim2real-fl-cli-"), scenario)
    sg_server = _sg(ctx, ec2, vpc, ctx.unique_name("sim2real-fl-srv-"), scenario)
    ec2.authorize_security_group_ingress(
        GroupId=sg_server,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": p_ok, "ToPort": p_ok,
                        "UserIdGroupPairs": [{"GroupId": sg_client}]}],
    )
    eni_client, ip_client = _eni(ctx, ec2, subnet, sg_client, scenario)
    eni_server, ip_server = _eni(ctx, ec2, subnet, sg_server, scenario)

    fl_ids = {t: _flow_log_cwl(ctx, ec2, eni_server, "NetworkInterface", t, g, role, FIELDS, scenario)
              for t, g in groups.items()}

    # negative: an unknown field in LogFormat is refused, and no flow log comes into being
    code, message = _error_code(lambda: ec2.create_flow_logs(
        ResourceIds=[eni_server], ResourceType="NetworkInterface", TrafficType="ALL",
        LogDestinationType="cloud-watch-logs", LogGroupName=groups["ALL"],
        DeliverLogsPermissionArn=role, LogFormat="${srcaddr} ${sim2real-not-a-field}",
        MaxAggregationInterval=60), ctx, ec2)
    assert code == "InvalidParameter", f"unknown LogFormat field returned {code!r}"
    expected = "Unknown fields provided: 'sim2real-not-a-field'"
    assert message == expected, (
        f"unknown LogFormat field message: expected {expected!r}, got {message!r}"
    )
    on_eni = _flow_logs_on(ec2, eni_server)
    assert on_eni == set(fl_ids.values()), (
        f"after the refused create the ENI carries {sorted(on_eni)!r}, expected exactly "
        f"{sorted(fl_ids.values())!r}"
    )

    _launch(ctx, ec2, ami, [
        (eni_server, _server_userdata([p_ok, p_block])),
        (eni_client, _client_userdata([
            (ip_server, p_ok, sp_ok),
            (ip_server, p_block, sp_block),
        ])),
    ], scenario)

    def acc(rs):
        return [r for r in rs if _is(r, ip_client, ip_server, sp_ok, p_ok)]

    def rej(rs):
        return [r for r in rs if _is(r, ip_client, ip_server, sp_block, p_block)]

    def want(out):
        if not (acc(out["ALL"]) and rej(out["ALL"]) and acc(out["ACCEPT"]) and rej(out["REJECT"])):
            return False
        first_rej = min(int(r["start"]) for r in rej(out["REJECT"]) + rej(out["ALL"]))
        first_acc = min(int(r["start"]) for r in acc(out["ALL"]) + acc(out["ACCEPT"]))
        # each filtered log must have delivered an interval AFTER the other action's traffic began
        return (max(int(r["start"]) for r in acc(out["ACCEPT"])) > first_rej
                and max(int(r["start"]) for r in rej(out["REJECT"])) > first_acc)

    out = _poll_cwl(logs, groups, FIELDS, want, budget_s=1200)
    now = int(time.time())

    # positive control: ALL carries both decisions
    assert {r["action"] for r in acc(out["ALL"])} == {"ACCEPT"}, f"ALL log accepts {acc(out['ALL'])!r}"
    assert {r["action"] for r in rej(out["ALL"])} == {"REJECT"}, f"ALL log rejects {rej(out['ALL'])!r}"
    for r in acc(out["ALL"]) + rej(out["ALL"]):
        assert r["protocol"] == "6" and int(r["packets"]) > 0, f"ALL log record {r!r}"
        assert r["log-status"] == "OK", f"captured interval log-status {r!r}"
        _in_window(r, t_run_start, now)

    # effect absent at the filter
    actions_accept = {r["action"] for r in out["ACCEPT"]}
    actions_reject = {r["action"] for r in out["REJECT"]}
    assert actions_accept == {"ACCEPT"}, f"TrafficType=ACCEPT log delivered actions {actions_accept!r}"
    assert actions_reject == {"REJECT"}, f"TrafficType=REJECT log delivered actions {actions_reject!r}"
    assert not rej(out["ACCEPT"]), f"ACCEPT log carried the blocked flow: {rej(out['ACCEPT'])!r}"
    assert not acc(out["REJECT"]), f"REJECT log carried the allowed flow: {acc(out['REJECT'])!r}"
    for r in acc(out["ACCEPT"]):
        assert int(r["bytes"]) > 0 and r["interface-id"] == eni_server, f"ACCEPT log record {r!r}"
        _in_window(r, t_run_start, now)
    for r in rej(out["REJECT"]):
        assert r["dstport"] == str(p_block) and r["interface-id"] == eni_server, f"REJECT rec {r!r}"
        _in_window(r, t_run_start, now)


def _error_code(fn, ctx, ec2):
    """The (code, message) of fn()'s refusal. If fn unexpectedly SUCCEEDS, tear down what it
    made and raise."""
    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    made = resp.get("FlowLogIds") or []
    if made:
        ctx.on_cleanup(lambda: ec2.delete_flow_logs(FlowLogIds=made))
    raise AssertionError(f"call expected to be refused succeeded: {resp!r}")


def _flow_logs_on(ec2, resource_id):
    ids = set()
    for page in ec2.get_paginator("describe_flow_logs").paginate(
            Filters=[{"Name": "resource-id", "Values": [resource_id]}]):
        ids |= {f["FlowLogId"] for f in page["FlowLogs"]}
    return ids



def _is(r, src, dst, sport, dport):
    return (r.get("srcaddr") == src and r.get("dstaddr") == dst
            and r.get("srcport") == str(sport) and r.get("dstport") == str(dport))


def _in_window(r, t0, t1):
    s, e = int(r["start"]), int(r["end"])
    assert t0 - 60 <= s <= e <= t1 + 60, (
        f"record start/end ({s}, {e}) not plausible epoch seconds in run window [{t0}, {t1}]: {r!r}"
    )


def _delivery_role(ctx, iam, account, partition, region, groups, scenario):
    """IAM role the flow-log service assumes to write to exactly these log groups."""
    name = ctx.unique_name("sim2real-fl-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
        "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": account}}}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": scenario}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    res = [f"arn:{partition}:logs:{region}:{account}:log-group:{g}:*" for g in groups]
    pol = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": res},
        {"Effect": "Allow", "Action": ["logs:DescribeLogGroups", "logs:DescribeLogStreams"],
         "Resource": "*"}]}
    iam.put_role_policy(RoleName=name, PolicyName="deliver", PolicyDocument=json.dumps(pol))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="deliver"))
    time.sleep(10)  # IAM propagation has no pollable condition; the bounded retry below decides
    return arn


def _log_group(ctx, logs, scenario):
    g = ctx.unique_name("/sim2real/flowlogs/")
    logs.create_log_group(logGroupName=g, tags={"sim2real": scenario})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=g))
    return g


def _flow_log_cwl(ctx, ec2, resource_id, resource_type, traffic, group, role_arn, fields, scenario):
    """CreateFlowLogs to CloudWatch Logs, retrying (bounded) only while the new role propagates."""
    deadline = time.time() + 180
    while True:
        fl = ec2.create_flow_logs(
            ResourceIds=[resource_id], ResourceType=resource_type, TrafficType=traffic,
            LogDestinationType="cloud-watch-logs", LogGroupName=group,
            DeliverLogsPermissionArn=role_arn,
            LogFormat=" ".join("${%s}" % f for f in fields), MaxAggregationInterval=60,
            TagSpecifications=_tags("vpc-flow-log", ctx.unique_name("sim2real-fl-"), scenario),
        )
        got = fl.get("FlowLogIds") or []
        if got:
            ctx.on_cleanup(lambda got=got: ec2.delete_flow_logs(FlowLogIds=got))
        bad = fl.get("Unsuccessful") or []
        if not bad and len(got) == 1:
            return got[0]
        msg = " ".join(str(u.get("Error", {}).get("Message", "")) for u in bad).lower()
        if "assume" in msg and time.time() < deadline:
            time.sleep(10)
            continue
        raise AssertionError(f"CreateFlowLogs({traffic} on {resource_id}) failed: {fl!r}")


def _poll_cwl(logs, groups, fields, want, budget_s):
    """groups: {label: log_group}. Poll every group until want({label: [records]}) holds."""
    deadline = time.time() + budget_s
    while True:
        out = {}
        for label, g in groups.items():
            recs = []
            for page in logs.get_paginator("filter_log_events").paginate(logGroupName=g):
                for ev in page.get("events", []):
                    toks = ev["message"].split(" ")
                    assert len(toks) == len(fields), (
                        f"record {ev['message']!r} in {g!r} has {len(toks)} fields, format has "
                        f"{len(fields)}")
                    r = dict(zip(fields, toks))
                    r["_stream"] = ev["logStreamName"]
                    recs.append(r)
            out[label] = recs
        if want(out):
            return out
        if time.time() > deadline:
            raise AssertionError(
                f"flow-log records for the caused connections never arrived within {budget_s}s: "
                + repr({k: v[:15] for k, v in out.items()}))
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
