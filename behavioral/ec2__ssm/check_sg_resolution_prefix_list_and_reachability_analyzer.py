"""sg-resolution-prefix-list-and-reachability-analyzer."""
from __future__ import annotations

import base64
import json
import sys
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sg-resolution-prefix-list-and-reachability-analyzer"
GROUP = "security-group-data-plane"
SERVICES = ["ec2", "ssm"]

_VPC_CIDR = "10.72.0.0/16"
_CLIENT_CIDR = "10.72.10.0/24"
_SERVER_CIDR = "10.72.11.0/24"
_ENDPOINT_CIDR = "10.72.20.0/24"
_SERVER_IP = "10.72.11.10"
_PORT = 8080
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
# curl(1): 28 is "Operation timeout" -- a silently DROPPED packet, which is what a security
# group's deny-by-default produces. 7 ("Failed to
# connect") would mean something answered with a reset instead, which never happens here.
_CURL_TIMEOUT = 28
_UNRELATED_PROBE_CIDR = "203.0.113.77/32"  # TEST-NET-3 (RFC 5737): never the client's own address
# Reachability Analyzer's one Explanation for an ENI whose attached security group admits nothing
# on the destination port names the group with ExplanationCode "ENI_SG_RULES_MISMATCH"
# (DirectionIn=True).
_SG_MISMATCH_CODE = "ENI_SG_RULES_MISMATCH"


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """An SG rule sourced from a managed prefix list follows the list's current membership; an
    unrelated list never admits the client even beside a CIDR rule that does; and Reachability
    Analyzer's verdict (ENI_SG_RULES_MISMATCH, then path found) agrees with real TCP packets.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"iface": [], "subnets": [], "sgs": [], "instances": [], "prefix_lists": [],
                "insights_paths": [], "insights_analyses": []}
    try:
        _build(ctx, ec2, ssm, iam, st)
        _part1_prefix_list_toggle(ctx, ec2, ssm, st)
        _part2_prefix_list_vs_cidr_twin(ctx, ec2, ssm, st)
        _part3_reachability_analyzer(ctx, ec2, ssm, st)
    finally:
        # In-band: terminating two instances and draining endpoint ENIs exceeds ctx.on_cleanup's
        # budget; on_cleanup still holds a fast, non-waiting second net on every resource.
        _teardown(ec2, iam, st)


# ===== the fixture ==========================================================
def _build(ctx, ec2, ssm, iam, st) -> None:
    region = ctx.region
    name = ctx.unique_name("sim2real-sgres-")
    st["name"], st["region"], st["nonce"] = name, region, name

    zones = _usable_zones(ec2, want=2)
    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    # No internet gateway and no route table of our own: the VPC's main route table carries only
    # the local route, so the two instances can reach each other and nothing else, and every
    # observation below is about the security group's own filtering rather than about egress.

    client_subnet = _create_subnet(ctx, ec2, st, _CLIENT_CIDR, zones[0], name + "-client")
    server_subnet = _create_subnet(ctx, ec2, st, _SERVER_CIDR, zones[1], name + "-server")
    endpoint_subnet = _create_subnet(ctx, ec2, st, _ENDPOINT_CIDR, zones[0], name + "-endpoint")
    st["client_subnet"], st["server_subnet"] = client_subnet, server_subnet

    sg_ep = _create_sg(ctx, ec2, st, name + "-endpoint", "sim2real sgres interface endpoints")
    ec2.authorize_security_group_ingress(
        GroupId=sg_ep,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                        "IpRanges": [{"CidrIp": _VPC_CIDR}]}])
    sg_client = _create_sg(ctx, ec2, st, name + "-client", "sim2real sgres client")
    sg_server = _create_sg(ctx, ec2, st, name + "-server", "sim2real sgres server")
    st["sg_server"] = sg_server
    # The server's security group starts with NO ingress rule on _PORT at all: every part below
    # proves reachability is a function of what gets authorized, never of anything ambient.

    # SSM reports each leg through interface endpoints in a third subnet, so edits to the server's
    # rules can never touch the channel carrying the result.
    for svc in ("ssm", "ssmmessages", "ec2messages"):
        ep = ec2.create_vpc_endpoint(
            VpcEndpointType="Interface", VpcId=vpc_id,
            ServiceName=f"com.amazonaws.{region}.{svc}",
            SubnetIds=[endpoint_subnet], SecurityGroupIds=[sg_ep], PrivateDnsEnabled=True,
            TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": _tags_for(name)}],
        )["VpcEndpoint"]["VpcEndpointId"]
        st["iface"].append(ep)
        ctx.on_cleanup(_gone_ok(lambda ep=ep: ec2.delete_vpc_endpoints(VpcEndpointIds=[ep])))
    for ep in st["iface"]:
        _poll(lambda ep=ep: _endpoint_state(ec2, ep), lambda s: s == "available",
              timeout_s=420, interval_s=2, what=f"interface endpoint {ep} becoming available")

    role_name = name + "-role"
    st["role"] = st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name)

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    server_user_data = (
        "#!/bin/bash\n"
        "mkdir -p /tmp/srv\n"
        f"printf '%s' '{st['nonce']}' > /tmp/srv/nonce\n"
        "cd /tmp/srv\n"
        f"nohup python3 -m http.server {_PORT} --bind 0.0.0.0 > /tmp/httpd.log 2>&1 &\n"
    )
    st["server"] = _launch(ctx, ec2, st, ami, server_subnet, sg_server, name + "-server",
                           user_data=server_user_data, private_ip=_SERVER_IP)
    st["client"] = _launch(ctx, ec2, st, ami, client_subnet, sg_client, name + "-client")

    for label, iid in (("server", st["server"]), ("client", st["client"])):
        info = _poll(lambda iid=iid: _agent_view(ssm, iid),
                     lambda i: i is not None and i.get("PingStatus") == "Online",
                     timeout_s=600, interval_s=2,
                     what=f"the SSM agent on the {label} {iid} coming Online through the "
                          f"interface endpoints {st['iface']!r}")
        assert info["PingStatus"] == "Online", f"the {label}'s agent view was {info!r}"

    # RunInstances is eventually consistent: DescribeInstances can 404 an id it has just minted.
    described = _call_with_retry(
        lambda: ec2.describe_instances(InstanceIds=[st["server"], st["client"]]),
        codes=_THROTTLE + ("InvalidInstanceID.NotFound",), retries=12, delay=5.0)["Reservations"]
    by_id = {i["InstanceId"]: i for r in described for i in r["Instances"]}
    assert by_id[st["server"]]["PrivateIpAddress"] == _SERVER_IP, (
        f"the server did not take the fixed address the parts target: "
        f"{by_id[st['server']]['PrivateIpAddress']!r}")
    st["client_ip"] = by_id[st["client"]]["PrivateIpAddress"]
    st["server_eni"] = by_id[st["server"]]["NetworkInterfaces"][0]["NetworkInterfaceId"]
    st["client_eni"] = by_id[st["client"]]["NetworkInterfaces"][0]["NetworkInterfaceId"]
    assert by_id[st["client"]]["Placement"]["AvailabilityZone"] != \
        by_id[st["server"]]["Placement"]["AvailabilityZone"], (
        "the two instances must sit in different AZs, so the parts also exercise cross-AZ "
        f"intra-VPC delivery; they are in {by_id[st['client']]['Placement']!r} and "
        f"{by_id[st['server']]['Placement']!r}")

    # --- the barrier: nothing below is interpretable unless the server serves ---
    local = _server_view(ssm, st)
    assert local["local"] == st["nonce"], (
        f"the server must answer its own listener on 127.0.0.1 before any part runs; it returned "
        f"{local['local']!r}, expected {st['nonce']!r}")


# ===== part 1: prefix-list membership edit, SG rule untouched ==============
def _part1_prefix_list_toggle(ctx, ec2, ssm, st) -> None:
    client_cidr = f"{st['client_ip']}/32"
    pl_id, version = _create_prefix_list(
        ctx, ec2, st, name_suffix="toggle", max_entries=2,
        entries=[{"Cidr": client_cidr, "Description": "client"}])
    assert version == 1, f"a freshly created prefix list must start at version 1, got {version}"

    rule_id = _authorize_from_prefix_list(ec2, st["sg_server"], pl_id)

    # 1a: reachable while the list holds the client's /32
    r1 = _reach(ssm, st, expect_ok=True,
               what="part1a: SG ingress sourced from a prefix list holding the client's /32")
    assert r1["rc"] == 0 and r1["body"] == st["nonce"], f"part1a did not reach the server: {r1!r}"
    hits1 = int(_server_view(ssm, st)["hits"])

    # 1b: remove the entry via ModifyManagedPrefixList -- the SG RULE is never touched
    version = _modify_prefix_list(ec2, pl_id, version, remove=[client_cidr])
    assert version == 2, f"removing the one entry must bump the version to 2, got {version}"
    entries = ec2.get_managed_prefix_list_entries(PrefixListId=pl_id)["Entries"]
    assert entries == [], f"the list must hold no entries after the removal, got {entries!r}"

    l1b, base1b, after1b = _blocked_leg(
        ssm, st, what="part1b: the client's /32 removed from the prefix list the SG rule names")
    assert l1b["body"] == "", f"part1b returned a body, so something answered: {l1b!r}"
    assert after1b["local"] == st["nonce"], (
        f"the server stopped serving, so part1b is not evidence about the SG rule: {after1b!r}")
    assert int(after1b["hits"]) == int(base1b["hits"]) and int(base1b["hits"]) >= hits1, (
        f"a security group with no admitting entry drops the SYN silently, so the server logs no "
        f"completed request; one further blocked attempt moved the log "
        f"{base1b['hits']!r} -> {after1b['hits']!r}")

    # 1c: re-add the SAME /32 -- a different edit, a second version bump, reachable again
    version = _modify_prefix_list(
        ec2, pl_id, version, add=[{"Cidr": client_cidr, "Description": "client-readd"}])
    assert version == 3, f"re-adding the entry must bump the version to 3, got {version}"
    r1c = _reach(ssm, st, expect_ok=True,
                what="part1c: the client's /32 re-added to the prefix list")
    assert r1c["rc"] == 0 and r1c["body"] == st["nonce"], f"part1c did not recover: {r1c!r}"
    hits1c = int(_server_view(ssm, st)["hits"])
    assert hits1c > int(after1b["hits"]), (
        f"part1c's request must reach the server and be logged: "
        f"{after1b['hits']!r} -> {hits1c!r}")

    # leave the SG back at "no rule on _PORT" so part 2 starts from the same known baseline
    _revoke_ingress_rule(ec2, st["sg_server"], rule_id)


# ===== part 2: an unrelated prefix list vs a CIDR twin ======================
def _part2_prefix_list_vs_cidr_twin(ctx, ec2, ssm, st) -> None:
    pl_id, version = _create_prefix_list(
        ctx, ec2, st, name_suffix="unrelated", max_entries=1,
        entries=[{"Cidr": _UNRELATED_PROBE_CIDR, "Description": "not the client"}])
    assert version == 1, f"a freshly created prefix list must start at version 1, got {version}"
    unrelated_rule = _authorize_from_prefix_list(ec2, st["sg_server"], pl_id)

    # 2a: the unrelated prefix list alone must never admit the client
    l2a, base2a, after2a = _blocked_leg(
        ssm, st, what="part2a: SG ingress sourced only from a prefix list holding an "
                      "unrelated /32")
    assert l2a["body"] == "", f"part2a returned a body, so something answered: {l2a!r}"
    assert int(after2a["hits"]) == int(base2a["hits"]), (
        f"the unrelated prefix list must never admit the client, so the server logs no "
        f"completed request: {base2a['hits']!r} -> {after2a['hits']!r}")

    # 2b: add the CIDR twin -- same port, names the real client -- beside the unrelated rule
    twin_rule = _authorize_from_cidr(ec2, st["sg_server"], f"{st['client_ip']}/32")
    still_present = _find_sg_rule(ec2, unrelated_rule)
    assert still_present is not None and still_present.get("PrefixListId") == pl_id, (
        f"the unrelated prefix-list rule must still be in place, or part2b proves nothing about "
        f"independence: {still_present!r}")
    r2b = _reach(ssm, st, expect_ok=True,
                what="part2b: a CIDR-sourced twin rule added beside the unrelated prefix list")
    assert r2b["rc"] == 0 and r2b["body"] == st["nonce"], (
        f"a CIDR rule naming the client must admit it regardless of the unrelated prefix-list "
        f"rule sitting beside it: {r2b!r}")
    hits2b = int(_server_view(ssm, st)["hits"])
    assert hits2b > int(after2a["hits"]), (
        f"part2b's request must reach the server and be logged: "
        f"{after2a['hits']!r} -> {hits2b!r}")

    # 2c: remove the CIDR twin, close the bracket -- the unrelated prefix list alone, again
    _revoke_ingress_rule(ec2, st["sg_server"], twin_rule)
    l2c, base2c, after2c = _blocked_leg(
        ssm, st, what="part2c: the CIDR twin removed, only the unrelated prefix list remains")
    assert l2c["body"] == "", f"part2c returned a body, so something answered: {l2c!r}"
    assert int(after2c["hits"]) == int(base2c["hits"]), (
        f"with the twin gone the unrelated prefix list must still never admit the client: "
        f"{base2c['hits']!r} -> {after2c['hits']!r}")

    # leave the SG back at "no rule on _PORT" so part 3 starts from the same known baseline
    _revoke_ingress_rule(ec2, st["sg_server"], unrelated_rule)


# ===== part 3: Reachability Analyzer must agree with the packet =============
def _part3_reachability_analyzer(ctx, ec2, ssm, st) -> None:
    # 3a: confirm the SG, as left by parts 1-2, admits nothing on _PORT, then prove it with a
    # real TCP attempt before asking the analyzer anything.
    current = ec2.describe_security_groups(GroupIds=[st["sg_server"]])["SecurityGroups"][0]
    on_port = [p for p in current["IpPermissions"]
               if p.get("FromPort") == _PORT and p.get("ToPort") == _PORT]
    assert on_port == [], (
        f"part3 must start with no ingress rule admitting {_PORT}; found {on_port!r}")
    l3a, base3a, after3a = _blocked_leg(
        ssm, st, what="part3a: no SG rule admits the client at all")
    assert l3a["body"] == "", f"part3a returned a body, so something answered: {l3a!r}"
    assert int(after3a["hits"]) == int(base3a["hits"]), (
        f"with no admitting rule the server must log no completed request: "
        f"{base3a['hits']!r} -> {after3a['hits']!r}")

    path_id = ec2.create_network_insights_path(
        Source=st["client_eni"], Destination=st["server_eni"], Protocol="tcp",
        DestinationPort=_PORT, ClientToken=str(uuid.uuid4()),
        TagSpecifications=[{"ResourceType": "network-insights-path",
                           "Tags": _tags_for(st["name"])}],
    )["NetworkInsightsPath"]["NetworkInsightsPathId"]
    st["insights_paths"].append(path_id)
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_network_insights_path(NetworkInsightsPathId=path_id)))

    analysis0 = _run_analysis(ctx, ec2, st, path_id)
    assert analysis0["Status"] == "succeeded", (
        f"the analysis must reach succeeded, not {analysis0['Status']!r}: "
        f"{analysis0.get('StatusMessage')!r}")
    assert analysis0["NetworkPathFound"] is False, (
        f"with no admitting SG rule the analyzer must report NetworkPathFound=False: "
        f"{analysis0!r}")
    sg_mismatch = [e for e in analysis0["Explanations"]
                  if _mentions(e, st["sg_server"]) and e.get("ExplanationCode") == _SG_MISMATCH_CODE]
    assert sg_mismatch, (
        f"the analyzer must name the server's security group {st['sg_server']!r} in an "
        f"Explanation carrying ExplanationCode {_SG_MISMATCH_CODE!r} while the path is blocked; "
        f"got {analysis0['Explanations']!r}")

    # 3b: authorize the one rule parts (1)-(2) already proved sufficient, re-prove with a real
    # packet, then re-analyse the SAME path and watch the verdict flip.
    rule_id = _authorize_from_cidr(ec2, st["sg_server"], f"{st['client_ip']}/32")
    r3b = _reach(ssm, st, expect_ok=True, what="part3b: the one CIDR rule authorized")
    assert r3b["rc"] == 0 and r3b["body"] == st["nonce"], f"part3b did not reach the server: {r3b!r}"

    analysis1 = _run_analysis(ctx, ec2, st, path_id)
    assert analysis1["Status"] == "succeeded", (
        f"the second analysis must reach succeeded, not {analysis1['Status']!r}: "
        f"{analysis1.get('StatusMessage')!r}")
    assert analysis1["NetworkPathFound"] is True, (
        f"with the one admitting rule in place the analyzer must flip to NetworkPathFound=True: "
        f"{analysis1!r}")

    _revoke_ingress_rule(ec2, st["sg_server"], rule_id)


def _run_analysis(ctx, ec2, st, path_id):
    resp = ec2.start_network_insights_analysis(
        NetworkInsightsPathId=path_id, ClientToken=str(uuid.uuid4()),
        TagSpecifications=[{"ResourceType": "network-insights-analysis",
                           "Tags": _tags_for(st["name"])}])
    analysis_id = resp["NetworkInsightsAnalysis"]["NetworkInsightsAnalysisId"]
    st["insights_analyses"].append(analysis_id)
    ctx.on_cleanup(_gone_ok(
        lambda: ec2.delete_network_insights_analysis(NetworkInsightsAnalysisId=analysis_id)))

    def probe():
        found = ec2.describe_network_insights_analyses(
            NetworkInsightsAnalysisIds=[analysis_id])["NetworkInsightsAnalyses"]
        assert found, f"analysis {analysis_id} disappeared mid-poll"
        return found[0]

    return _poll(probe, lambda a: a["Status"] in ("succeeded", "failed"),
                timeout_s=240, interval_s=2,
                what=f"analysis {analysis_id} on path {path_id} reaching a terminal status")


def _mentions(obj, needle) -> bool:
    """Recursively search a nested Explanation structure for an exact value match, so the
    assertion does not depend on which field happens to carry the security-group id."""
    if isinstance(obj, dict):
        return any(_mentions(v, needle) for v in obj.values())
    if isinstance(obj, list):
        return any(_mentions(v, needle) for v in obj)
    return obj == needle


# ===== in-band teardown =====================================================
def _teardown(ec2, iam, st) -> list:
    """Ordered teardown with the waits `ctx.on_cleanup`'s 60 s budget cannot afford. Runs every
    step, then raises what it could not remove, naming any failure in flight so it is not masked."""
    left = []
    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    def _vpc_gone(vpc_id):
        still = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
        raise AssertionError(f"vpc {vpc_id} is still describable: {still!r}")

    for aid in st.get("insights_analyses", []):
        _step(f"insights-analysis {aid}",
              lambda a=aid: ec2.delete_network_insights_analysis(NetworkInsightsAnalysisId=a))
    for pid in st.get("insights_paths", []):
        _step(f"insights-path {pid}",
              lambda p=pid: ec2.delete_network_insights_path(NetworkInsightsPathId=p))

    for iid in st.get("instances", []):
        _step(f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
    for iid in st.get("instances", []):
        _step(f"instance-wait {iid}", lambda i=iid: _wait_terminated(ec2, i))
    if st.get("iface"):
        _step("endpoints", lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=st["iface"]))
        _step("endpoints-deleted", lambda: _poll(
            lambda: [e for e in st["iface"]
                     if _endpoint_state(ec2, e) not in ("deleted", "gone")],
            lambda pending: pending == [], timeout_s=300, interval_s=2,
            what="the interface endpoints reporting deleted"))
    if st.get("vpc"):
        _step("eni-drain", lambda: _poll(
            lambda: _vpc_enis(ec2, st["vpc"]), lambda enis: enis == [],
            timeout_s=420, interval_s=2,
            what=f"every ENI in {st['vpc']!r} draining"))
    if st.get("profile"):
        _step("instance-profile", lambda: _drop_instance_profile(iam, st["profile"], st["role"]))
    if st.get("role"):
        _step("role", lambda: _drop_role(iam, st["role"]))
    # security groups BEFORE prefix lists: deleting a group drops every rule that referenced one
    # of our managed prefix lists, which is the only thing that can hold a prefix-list delete back.
    for sg in reversed(st.get("sgs", [])):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s)))
    for pl in st.get("prefix_lists", []):
        _step(f"prefix-list {pl}", lambda p=pl: _retry_dependency(
            lambda: ec2.delete_managed_prefix_list(PrefixListId=p)))
    for subnet in st.get("subnets", []):
        _step(f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s)))
    if st.get("vpc"):
        _step("vpc", lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=st["vpc"])))
        _step("vpc-gone", lambda: _vpc_gone(st["vpc"]))
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _GONE_CODES and (code is None or "NotFound" not in code):
                left.append(f"{label}: {code}")
        except Exception as exc:  # noqa: BLE001 — collected, raised after every step
            left.append(f"{label}: {exc!r}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError((f"{found!r}; " if found else "")
                             + f"teardown could not remove everything the check created: {left!r}")
    return left


# ===== helpers =====================================
_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
               "InvalidVpcEndpointId.NotFound", "InvalidPrefixListID.NotFound",
               "InvalidNetworkInsightsPathId.NotFound",
               "InvalidNetworkInsightsAnalysisId.NotFound")


def _gone_ok(fn):
    """A cleanup step that tolerates the resource being gone already: the ordered teardown in the
    `finally` deletes the same resources first, so this second net finds most of them absent."""

    def step():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
                raise

    return step


def _tags_for(name):
    return [{"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": "sgres"},
            {"Key": "sim2real:managed", "Value": "true"}]


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)


def _retry_dependency(fn, timeout_s=240, interval_s=2):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DependencyViolation" \
                    and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _usable_zones(ec2, want):
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert len(usable) >= want, (
        f"this region offers {_INSTANCE_TYPE} in {usable!r}, and the check needs {want} zones")
    return usable[:want]


def _create_subnet(ctx, ec2, st, cidr, zone, tag_name):
    subnet_id = ec2.create_subnet(
        VpcId=st["vpc"], CidrBlock=cidr, AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(tag_name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return subnet_id


def _create_sg(ctx, ec2, st, group_name, description):
    sg = ec2.create_security_group(
        GroupName=group_name, Description=description, VpcId=st["vpc"],
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(group_name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_security_group(GroupId=sg)))
    return sg


def _create_prefix_list(ctx, ec2, st, name_suffix, max_entries, entries):
    pl_id = ec2.create_managed_prefix_list(
        PrefixListName=st["name"] + "-pl-" + name_suffix,
        AddressFamily="IPv4", MaxEntries=max_entries, Entries=entries,
        TagSpecifications=[{"ResourceType": "prefix-list", "Tags": _tags_for(st["name"])}],
    )["PrefixList"]["PrefixListId"]
    st["prefix_lists"].append(pl_id)
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id)))
    described = _wait_prefix_list_stable(ec2, pl_id)
    assert described["State"] == "create-complete", (
        f"prefix list {pl_id} must settle create-complete, got {described!r}")
    return pl_id, described["Version"]


def _modify_prefix_list(ec2, pl_id, current_version, add=None, remove=None):
    kwargs = {"PrefixListId": pl_id, "CurrentVersion": current_version}
    if add:
        kwargs["AddEntries"] = add
    if remove:
        kwargs["RemoveEntries"] = [{"Cidr": c} for c in remove]
    resp = ec2.modify_managed_prefix_list(**kwargs)
    assert resp["PrefixList"]["State"] == "modify-in-progress", (
        f"expected modify-in-progress immediately after the call, got "
        f"{resp['PrefixList']['State']!r}")
    described = _wait_prefix_list_stable(ec2, pl_id)
    assert described["State"] == "modify-complete", (
        f"prefix list {pl_id} must settle modify-complete, got {described!r}")
    return described["Version"]


def _wait_prefix_list_stable(ec2, pl_id, timeout_s=120, interval_s=3):
    deadline = time.monotonic() + timeout_s
    described = None
    while time.monotonic() < deadline:
        described = ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0]
        if described["State"].endswith("-complete") or described["State"].endswith("-failed"):
            return described
        time.sleep(interval_s)
    raise AssertionError(f"prefix list {pl_id} not stable within {timeout_s}s (last {described!r})")


def _authorize_from_prefix_list(ec2, group_id, pl_id):
    resp = ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                        "PrefixListIds": [{"PrefixListId": pl_id,
                                          "Description": "sim2real sgres"}]}])
    rules = resp["SecurityGroupRules"]
    assert len(rules) == 1, f"expected exactly one rule minted, got {rules!r}"
    return rules[0]["SecurityGroupRuleId"]


def _authorize_from_cidr(ec2, group_id, cidr):
    resp = ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                        "IpRanges": [{"CidrIp": cidr, "Description": "sim2real sgres"}]}])
    rules = resp["SecurityGroupRules"]
    assert len(rules) == 1, f"expected exactly one rule minted, got {rules!r}"
    return rules[0]["SecurityGroupRuleId"]


def _revoke_ingress_rule(ec2, group_id, rule_id):
    ec2.revoke_security_group_ingress(GroupId=group_id, SecurityGroupRuleIds=[rule_id])


def _find_sg_rule(ec2, rule_id):
    rules = ec2.describe_security_group_rules(
        SecurityGroupRuleIds=[rule_id])["SecurityGroupRules"]
    return rules[0] if rules else None


def _endpoint_state(ec2, endpoint_id):
    try:
        eps = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidVpcEndpointId.NotFound":
            return "gone"
        raise
    return eps[0]["State"] if eps else "gone"


def _vpc_enis(ec2, vpc_id):
    return [e["NetworkInterfaceId"] for e in ec2.describe_network_interfaces(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkInterfaces"]]


def _create_instance_role(ctx, iam, role_name):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real sgres prefix-list and reachability analyzer",
                    Tags=[{"Key": "sim2real", "Value": "sgres"}])
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(_gone_ok(lambda: iam.detach_role_policy(RoleName=role_name,
                                                  PolicyArn=_SSM_CORE_POLICY)))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "sgres"}])
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(_gone_ok(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=role_name, RoleName=role_name)))
    # IAM exposes no "this role is usable" condition to poll. `_launch`'s own bounded retry on
    # InvalidParameterValue (below) is what actually makes this correct; no sleep is needed here.


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(10):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                break
            if attempt == 9:
                raise
            time.sleep(5)
    iam.delete_instance_profile(InstanceProfileName=profile_name)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    for attempt in range(10):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DeleteConflict" and attempt < 9:
                time.sleep(5)
                continue
            raise


def _launch(ctx, ec2, st, ami, subnet_id, sg_id, tag_name, user_data=None, private_ip=None):
    nic = {"DeviceIndex": 0, "SubnetId": subnet_id, "Groups": [sg_id],
           "AssociatePublicIpAddress": False}
    if private_ip:
        nic["PrivateIpAddress"] = private_ip
    kwargs = dict(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        NetworkInterfaces=[nic], IamInstanceProfile={"Name": st["profile"]},
        MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
        TagSpecifications=[{"ResourceType": rt, "Tags": _tags_for(tag_name)}
                           for rt in ("instance", "volume")],
    )
    if user_data:
        kwargs["UserData"] = base64.b64encode(user_data.encode()).decode()
    iid = _call_with_retry(lambda: ec2.run_instances(**kwargs),
                           codes=_THROTTLE + ("InvalidParameterValue",),
                           retries=30, delay=5.0)["Instances"][0]["InstanceId"]
    st["instances"].append(iid)
    # Registered BEFORE any readiness poll: a host that never registers must not strand billing.
    ctx.on_cleanup(_gone_ok(lambda: ec2.terminate_instances(InstanceIds=[iid])))
    return iid


def _wait_terminated(ec2, instance_id, timeout_s=420):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = [i["State"]["Name"]
                  for r in _call_with_retry(
                      lambda: ec2.describe_instances(InstanceIds=[instance_id]),
                      codes=_THROTTLE + ("InvalidInstanceID.NotFound",),
                      retries=12, delay=5.0)["Reservations"]
                  for i in r["Instances"]]
        if all(s == "terminated" for s in states):
            return
        time.sleep(2)
    raise AssertionError(f"instance {instance_id} never reached terminated within {timeout_s}s")


def _agent_view(ssm, instance_id):
    for page in ssm.get_paginator("describe_instance_information").paginate():
        for info in page["InstanceInformationList"]:
            if info.get("InstanceId") == instance_id:
                return info
    return None


def _run_phase(ssm, instance_id, script, timeout_s=300):
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]}, TimeoutSeconds=600,
        Comment="sim2real sgres leg"))
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    return _poll(_inv, lambda i: i is not None and i.get("Status") in _TERMINAL,
                 timeout_s=timeout_s, interval_s=5.0,
                 what=f"invocation {command_id} reaching a terminal status")


def _stdout(inv):
    assert inv["ResponseCode"] == 0, (
        f"the control command itself failed on the host: rc={inv['ResponseCode']!r} "
        f"stderr={inv.get('StandardErrorContent')!r}")
    return inv["StandardOutputContent"].strip()


def _json_line(inv):
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, (
        f"the guest reported no stdout: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}")
    return json.loads(lines[-1])


def _client_script():
    # /tmp/body is removed first: curl only truncates its output file once bytes arrive, so a leg
    # that times out would otherwise report the PREVIOUS leg's body and read as reachable.
    return f"""set -uo pipefail
rm -f /tmp/body
CODE=$(curl -s -m 8 -o /tmp/body -w '%{{http_code}}' http://{_SERVER_IP}:{_PORT}/nonce)
RC=$?
export CODE RC
python3 - <<'JEOF'
import json, os
d = {{"rc": int(os.environ.get("RC", "-1")), "code": os.environ.get("CODE", "")}}
try:
    with open("/tmp/body") as fh:
        d["body"] = fh.read()[:200]
except OSError:
    d["body"] = ""
print(json.dumps(d))
JEOF
"""


def _server_script(client_ip):
    return f"""set -uo pipefail
LOCAL=$(curl -s -m 5 http://127.0.0.1:{_PORT}/nonce || true)
HITS=$(grep -c '{client_ip}' /tmp/httpd.log || true)
export LOCAL HITS
python3 - <<'JEOF'
import json, os
print(json.dumps({{"local": os.environ.get("LOCAL", ""),
                  "hits": os.environ.get("HITS", "") or "0"}}))
JEOF
"""


def _server_view(ssm, st):
    return _json_line(_run_phase(ssm, st["server"], _server_script(st["client_ip"])))


def _blocked_leg(ssm, st, what):
    """Converge to blocked, then prove ONE more identical attempt leaves the server's access log
    untouched. The baseline is taken after convergence because attempts made before the rule
    change took effect do reach the server and get logged."""
    first = _reach(ssm, st, expect_ok=False, what=what)
    assert first["rc"] == _CURL_TIMEOUT, (
        f"a DROPPED packet must time the client out (curl {_CURL_TIMEOUT}), not be refused "
        f"(curl 7): {first!r} for {what}")
    base = _server_view(ssm, st)
    again = _json_line(_run_phase(ssm, st["client"], _client_script()))
    assert again["rc"] == _CURL_TIMEOUT, (
        f"a second identical attempt must be blocked too, or the block was a transient: "
        f"{again!r} for {what}")
    assert again["body"] == "", f"the repeat attempt returned a body: {again!r} for {what}"
    return again, base, _server_view(ssm, st)


def _reach(ssm, st, expect_ok, what):
    """Drive one leg from the client and poll until the expected outcome, so a security-group or
    prefix-list change that has not converged yet is a retry and a change that never converges is
    a FAIL naming what was last seen."""
    return _poll(lambda: _json_line(_run_phase(ssm, st["client"], _client_script())),
                 lambda r: (r["rc"] == 0) is expect_ok,
                 timeout_s=300, interval_s=5.0, what=what)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
