"""efs-nfs-two-node-posix-coherence-and-a-nonempty-rmdir-is-rejected."""
from __future__ import annotations

import concurrent.futures
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Three properties make every assertion cross-client and POSIX:
#   1. TWO instances in TWO availability zones, so every cross-node assertion is genuinely
#      cross-client rather than a round trip through one node's page cache.
#   2. The mount is PROVEN to be NFS (`findmnt -no FSTYPE` is exactly `nfs4`) before anything
#      else runs.
#   3. POSIX primitives are called directly from stdlib `python3` on the node -- `os.open` with
#      O_APPEND, `os.link`, `os.rename`, `os.rmdir`, `os.fsync`, `os.stat` -- rather than
#      approximated by `tee` and `cat`.
#
# NOT asserted, deliberately: a LOSSLESS interleaved append. The Linux NFS client implements
# O_APPEND by writing at a size it read first, so two clients appending concurrently may land two
# records on one offset. That is NFS, not a defect, and asserting no loss would fail a faithful
# emulator. What IS asserted is that no record is ever TORN -- which an object store backing each
# write with a PUT cannot satisfy.

_MOUNT_POINT = "/mnt/sim2real-efs"
_RECORD_SIZE = 512
_RECORDS_PER_NODE = 200
_FS_TIMEOUT_S = 300.0
_MT_TIMEOUT_S = 300.0
_SSM_ONLINE_TIMEOUT_S = 600.0
_SSM_COMMAND_TIMEOUT_S = 900.0
_NODE_BARRIER_TIMEOUT_S = 420.0
_SSM_MANAGED_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

# The per-node driver. One SSM invocation per instance, both in flight at once; the two nodes
# step through the phases in lockstep using files on the shared filesystem as barriers, which is
# also why the barriers themselves are evidence -- a node cannot see the peer's barrier file
# unless the filesystem really is shared.
_NODE_SCRIPT = r'''
import errno, hashlib, json, os, sys, time

MP = "__MOUNT_POINT__"
ME = sys.argv[1]
PEER = "B" if ME == "A" else "A"
N = __RECORDS__
RECSIZE = __RECSIZE__
DEADLINE = time.monotonic() + __BARRIER__
out = {"node": ME}


def touch(name):
    with open(os.path.join(MP, name), "wb") as handle:
        handle.write(b"x")
        handle.flush()
        os.fsync(handle.fileno())


def wait(name):
    path = os.path.join(MP, name)
    while time.monotonic() < DEADLINE:
        if os.path.exists(path):
            return
        time.sleep(0.25)
    raise SystemExit("barrier %s never appeared on the shared filesystem" % name)


def record(node, index):
    tag = ("%s:%04d:" % (node, index)).encode()
    body = tag + b"." * (RECSIZE - 65 - len(tag))
    return body + hashlib.sha256(body).hexdigest().encode() + b"\n"


def valid(chunk):
    return (len(chunk) == RECSIZE and chunk[-1:] == b"\n"
            and hashlib.sha256(chunk[:-65]).hexdigest().encode() == chunk[-65:-1])


# ---- phase 0: the mount is really NFS ----
out["fstype"] = os.popen("findmnt -no FSTYPE " + MP).read().strip()
out["fstype_magic"] = os.popen("stat -f -c %T " + MP).read().strip()
out["f_bsize"] = os.statvfs(MP).f_bsize

# ---- phase 1: concurrent O_APPEND from both nodes into one file ----
touch("ready-" + ME)
wait("ready-" + PEER)
shared = os.path.join(MP, "shared.log")
fd = os.open(shared, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o666)
for i in range(N):
    os.write(fd, record(ME, i))
    os.fsync(fd)
os.close(fd)
own = os.path.join(MP, "own-%s.log" % ME)
fd = os.open(own, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o666)
for i in range(N):
    os.write(fd, record(ME, i))
    os.fsync(fd)
os.close(fd)
touch("append-done-" + ME)
wait("append-done-" + PEER)

V1 = hashlib.sha256(b"v1" * 4096).digest() * 4
V2 = hashlib.sha256(b"v2" * 4096).digest() * 4
out["v1_sha"] = hashlib.sha256(V1).hexdigest()
out["v2_sha"] = hashlib.sha256(V2).hexdigest()
LINKED = hashlib.sha256(b"linked").digest() * 8
out["linked_sha"] = hashlib.sha256(LINKED).hexdigest()

if ME == "A":
    # ---- phase 2 (A): lay down everything B will observe, each fsync'd and closed ----
    for name, blob in (("live", V1), ("staging", V2)):
        with open(os.path.join(MP, name), "wb") as handle:
            handle.write(blob)
            handle.flush()
            os.fsync(handle.fileno())
    os.mkdir(os.path.join(MP, "hl"))
    with open(os.path.join(MP, "hl", "a"), "wb") as handle:
        handle.write(LINKED)
        handle.flush()
        os.fsync(handle.fileno())
    os.link(os.path.join(MP, "hl", "a"), os.path.join(MP, "hl", "b"))
    os.mkdir(os.path.join(MP, "ne"))
    with open(os.path.join(MP, "ne", "f"), "wb") as handle:
        handle.write(b"occupant")
        handle.flush()
        os.fsync(handle.fileno())
    touch("A2-done")

    # ---- phase 4 (A): rename over `live` while B is reading it in a loop ----
    wait("obs-ready")
    time.sleep(0.5)
    os.rename(os.path.join(MP, "staging"), os.path.join(MP, "live"))
    touch("renamed")

    # ---- phase 6 (A): drop one of the two hard links ----
    wait("obs-done")
    os.unlink(os.path.join(MP, "hl", "a"))
    touch("unlinked")

    # ---- phase 8 (A): the positive control for B's ENOTEMPTY ----
    wait("ne-cleared")
    os.rmdir(os.path.join(MP, "ne"))
    out["rmdir_after_clear"] = "ok"
    out["ne_present_after_rmdir"] = os.path.exists(os.path.join(MP, "ne"))
    touch("A-final")
else:
    wait("A2-done")
    # ---- phase 3 (B): read the shared append log written by BOTH nodes ----
    with open(os.path.join(MP, "shared.log"), "rb") as handle:
        blob = handle.read()
    out["shared_len"] = len(blob)
    chunks = [blob[i:i + RECSIZE] for i in range(0, len(blob), RECSIZE)]
    out["shared_records"] = len(chunks)
    out["shared_all_valid"] = all(valid(c) for c in chunks)
    out["shared_tags"] = sorted({c[:1].decode("ascii", "replace") for c in chunks})
    with open(os.path.join(MP, "own-A.log"), "rb") as handle:
        own_a = handle.read()
    out["own_a_len"] = len(own_a)
    own_chunks = [own_a[i:i + RECSIZE] for i in range(0, len(own_a), RECSIZE)]
    out["own_a_all_valid"] = all(valid(c) for c in own_chunks)
    out["own_a_tags_a"] = sum(1 for c in own_chunks if c[:2] == b"A:")

    # ---- phase 3 (B): close-to-open -- A's fsync'd, closed write is visible on B's next open ----
    with open(os.path.join(MP, "live"), "rb") as handle:
        out["live_before_sha"] = hashlib.sha256(handle.read()).hexdigest()

    # ---- phase 3 (B): the hard link, seen by the node that created neither path ----
    st_a = os.stat(os.path.join(MP, "hl", "a"))
    st_b = os.stat(os.path.join(MP, "hl", "b"))
    out["nlink_a"] = st_a.st_nlink
    out["nlink_b"] = st_b.st_nlink
    out["same_inode"] = st_a.st_ino == st_b.st_ino

    # ---- phase 3 (B): the refusal -- rmdir on a non-empty directory ----
    try:
        os.rmdir(os.path.join(MP, "ne"))
        out["rmdir_errno"] = "SUCCEEDED"
    except OSError as exc:
        out["rmdir_errno"] = errno.errorcode.get(exc.errno, str(exc.errno))
    # effect-absent: the directory and its occupant are untouched
    out["ne_still_there"] = os.path.isdir(os.path.join(MP, "ne"))
    with open(os.path.join(MP, "ne", "f"), "rb") as handle:
        out["ne_occupant"] = handle.read().decode()

    # ---- phase 5 (B): observe every distinct content of `live` across A's rename ----
    # The window is 60s, not the rename's own latency: Linux's NFS client caches a
    # directory's attributes for up to `acdirmax` (default 60s, `man 5 nfs`) before it will
    # re-validate a name lookup against the server, so a peer legitimately may not notice a
    # renamed entry until that cache expires even though the rename itself is instantaneous
    # server-side. `rename_seen_at_s` records how long it actually took on this run, so a
    # too-short window shows up as evidence instead of a flake.
    touch("obs-ready")
    seen = []
    seen_at_s = []
    errs = []
    start = time.monotonic()
    watch = start + 60.0
    digest = None
    while time.monotonic() < watch:
        try:
            with open(os.path.join(MP, "live"), "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
            if digest not in seen:
                seen.append(digest)
                seen_at_s.append(round(time.monotonic() - start, 2))
        except OSError as exc:
            errs.append(errno.errorcode.get(exc.errno, str(exc.errno)))
        if os.path.exists(os.path.join(MP, "renamed")) and digest == out["v2_sha"]:
            break
    out["rename_seen"] = seen
    out["rename_seen_at_s"] = seen_at_s
    out["rename_errors"] = errs
    with open(os.path.join(MP, "live"), "rb") as handle:
        out["live_after_sha"] = hashlib.sha256(handle.read()).hexdigest()
    touch("obs-done")

    # ---- phase 7 (B): the surviving link still holds the data ----
    wait("unlinked")
    out["a_gone"] = not os.path.exists(os.path.join(MP, "hl", "a"))
    st_b = os.stat(os.path.join(MP, "hl", "b"))
    out["nlink_b_after"] = st_b.st_nlink
    with open(os.path.join(MP, "hl", "b"), "rb") as handle:
        out["b_sha_after"] = hashlib.sha256(handle.read()).hexdigest()
    os.unlink(os.path.join(MP, "ne", "f"))
    touch("ne-cleared")
    wait("A-final")

print("SIM2REAL_JSON " + json.dumps(out))
'''


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _two_zones(ec2, instance_type, *, ctx):
    """The shared network's zones that offer the instance type."""
    offered = {
        offering["Location"]
        for offering in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        zone["ZoneName"]
        for zone in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if zone["ZoneName"] in offered and zone["ZoneName"] in ctx.network().availability_zones
    )
    assert len(usable) >= 2, (
        f"this region has {len(usable)} availability zone(s) offering {instance_type!r} "
        f"({usable!r}) in the run's shared network; a two-node cross-AZ check needs two"
    )
    return usable[:2]


def _subnets_in(zones, *, ctx):
    """The shared network's public subnet in each of `zones`; `Network.subnets` maps zone to subnet id
    and every network subnet is public."""
    net = ctx.network()
    missing = [zone for zone in zones if zone not in net.subnets]
    assert not missing, (
        f"the run's shared network {net.vpc_id} has no subnet in {missing!r}; the nodes need a "
        f"public subnet so `dnf install nfs-utils` can reach the AL2023 repositories without a NAT"
    )
    return net.vpc_id, [net.subnets[zone] for zone in zones]


def _wait_ssm_online(ssm, instance_id, timeout_s):
    def _probe():
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"]
        return info[0]["PingStatus"] if info else None

    return _poll_until(_probe, lambda s: s == "Online", timeout_s=timeout_s, interval_s=10.0)


def _run_node(ssm, instance_id, script, timeout_s):
    command_id = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]},
        TimeoutSeconds=int(timeout_s),
    )["Command"]["CommandId"]
    terminal = {"Success", "Failed", "Cancelled", "TimedOut"}

    def _probe():
        # SendCommand returns before the per-instance invocation is registered, so the first few
        # GetCommandInvocation calls raise InvocationDoesNotExist. That is registration latency,
        # not a missing command; every other error is real and propagates.
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    return _poll_until(
        _probe,
        lambda inv: inv is not None and inv["Status"] in terminal,
        timeout_s=timeout_s,
        interval_s=5.0,
    )


def _node_result(invocation, node):
    stdout = invocation.get("StandardOutputContent", "")
    assert invocation["Status"] == "Success", (
        f"node {node}'s script ended {invocation['Status']!r}; stderr tail "
        f"{invocation.get('StandardErrorContent', '')[-600:]!r}; stdout tail {stdout[-600:]!r}"
    )
    marker = "SIM2REAL_JSON "
    line = next((ln for ln in stdout.splitlines() if ln.startswith(marker)), None)
    assert line is not None, f"node {node} printed no result line; stdout tail {stdout[-600:]!r}"
    return json.loads(line[len(marker):])


def _delete_instances_verified(ec2, instance_ids):
    ec2.terminate_instances(InstanceIds=instance_ids)
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=instance_ids, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


def _delete_mt_verified(efs, mt_id):
    try:
        efs.delete_mount_target(MountTargetId=mt_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "MountTargetNotFound":
            raise
        return
    deadline = time.monotonic() + _MT_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            efs.describe_mount_targets(MountTargetId=mt_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "MountTargetNotFound":
                return
            raise
        time.sleep(2.0)
    raise AssertionError(f"mount target {mt_id} still present after {_MT_TIMEOUT_S}s")


def _delete_fs_verified(efs, fs_id):
    # FileSystemInUse while a mount target is still being released; retried to the deadline.
    deadline = time.monotonic() + _FS_TIMEOUT_S
    while True:
        try:
            efs.delete_file_system(FileSystemId=fs_id)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "FileSystemNotFound":
                return
            if code != "FileSystemInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)
    while time.monotonic() < deadline:
        try:
            efs.describe_file_systems(FileSystemId=fs_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "FileSystemNotFound":
                return
            raise
        time.sleep(2.0)
    raise AssertionError(f"file system {fs_id} still present after {_FS_TIMEOUT_S}s")


def _delete_sg_verified(ec2, sg_id):
    # DependencyViolation until the mount targets' and instances' ENIs are actually released,
    # which lags MountTargetNotFound and instance_terminated by minutes.
    deadline = time.monotonic() + 420.0
    last = None
    while time.monotonic() < deadline:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation":
                raise
            last = exc
            time.sleep(2.0)
    raise AssertionError(f"security group {sg_id} could not be deleted: {last}")


def _delete_role_verified(iam, role_name):
    for call in (
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=role_name, RoleName=role_name
        ),
        lambda: iam.delete_instance_profile(InstanceProfileName=role_name),
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            call()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise


CHECK = "efs-nfs-two-node-posix-coherence-and-a-nonempty-rmdir-is-rejected"
GROUP = 'rejected'
SERVICES = ['efs']


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """EFS mounted over NFSv4.1 by two nodes in two AZs shares inodes across hard links, renames
    atomically to the peer, shows close-to-open writes, never tears a concurrent append, and
    refuses rmdir on a non-empty directory with ENOTEMPTY."""
    efs = ctx.client("efs")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    instance_type = "t3.micro"

    zones = _two_zones(ec2, instance_type, ctx=ctx)
    vpc_id, subnet_ids = _subnets_in(zones, ctx=ctx)

    token = ctx.unique_name("sim2real-behav-efs-2node-")
    fs_id = efs.create_file_system(
        CreationToken=token, Encrypted=True, ThroughputMode="elastic",
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "Name", "Value": token}],
    )["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_verified(efs, fs_id))
    _poll_until(
        lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"],
        lambda state: state == "available",
        timeout_s=_FS_TIMEOUT_S,
    )

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-efs-2node-sg-"),
        Description="sim2real EFS two-node POSIX coherence check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_verified(ec2, sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 2049, "ToPort": 2049,
                        "UserIdGroupPairs": [{"GroupId": sg_id}]}],
    )

    role_name = ctx.unique_name("sim2real-behav-efs-2node-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY)
    iam.create_instance_profile(InstanceProfileName=role_name)
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _delete_role_verified(iam, role_name))

    for subnet_id in subnet_ids:
        mt_id = efs.create_mount_target(
            FileSystemId=fs_id, SubnetId=subnet_id, SecurityGroups=[sg_id]
        )["MountTargetId"]
        ctx.on_cleanup(lambda mt=mt_id: _delete_mt_verified(efs, mt))
        _poll_until(
            lambda mt=mt_id: efs.describe_mount_targets(
                MountTargetId=mt)["MountTargets"][0]["LifeCycleState"],
            lambda state: state == "available",
            timeout_s=_MT_TIMEOUT_S,
        )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    instance_ids = []
    # IAM instance-profile propagation exposes no condition to poll, so RunInstances gets the
    # bounded retry on the one error it produces while the profile is still settling.
    for index, subnet_id in enumerate(subnet_ids):
        deadline = time.monotonic() + 180.0
        last = None
        while time.monotonic() < deadline:
            try:
                instance_ids.append(ec2.run_instances(
                    ImageId=ami_id, InstanceType=instance_type, MinCount=1, MaxCount=1,
                    SubnetId=subnet_id, SecurityGroupIds=[sg_id],
                    IamInstanceProfile={"Name": role_name},
                    TagSpecifications=[{"ResourceType": "instance", "Tags": [
                        {"Key": "sim2real", "Value": CHECK},
                        {"Key": "Name", "Value": f"{token}-{index}"}]}],
                )["Instances"][0]["InstanceId"])
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "InvalidParameterValue":
                    raise
                last = exc
                time.sleep(5.0)
        else:
            raise AssertionError(f"RunInstances never succeeded in subnet {subnet_id}: {last}")
    ctx.on_cleanup(lambda: _delete_instances_verified(ec2, instance_ids))
    assert len(instance_ids) == 2, f"launched {instance_ids!r}, expected two instances"

    ec2.get_waiter("instance_running").wait(
        InstanceIds=instance_ids, WaiterConfig={"Delay": 2, "MaxAttempts": 200}
    )
    for instance_id in instance_ids:
        _wait_ssm_online(ssm, instance_id, _SSM_ONLINE_TIMEOUT_S)

    # Substitution by literal replacement, not str.format: the node script contains set
    # comprehensions, whose braces str.format would try to interpret as fields.
    body = _NODE_SCRIPT
    for placeholder, value in (("__MOUNT_POINT__", _MOUNT_POINT),
                               ("__RECORDS__", str(_RECORDS_PER_NODE)),
                               ("__RECSIZE__", str(_RECORD_SIZE)),
                               ("__BARRIER__", str(_NODE_BARRIER_TIMEOUT_S))):
        body = body.replace(placeholder, value)
    target = f"{fs_id}.efs.{ctx.region}.amazonaws.com:/"

    def _script(node):
        return (
            "set -e\n"
            "dnf install -y -q nfs-utils >/dev/null\n"
            f"test -e /sbin/mount.nfs4 || test -e /usr/sbin/mount.nfs4\n"
            f"mkdir -p {_MOUNT_POINT}\n"
            f"mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,"
            f"retrans=2,noresvport {target} {_MOUNT_POINT}\n"
            f"chmod 0777 {_MOUNT_POINT}\n"
            f"cat > /var/tmp/node.py <<'SIM2REAL_EOF'\n{body}\nSIM2REAL_EOF\n"
            f"python3 /var/tmp/node.py {node}\n"
            f"umount {_MOUNT_POINT}\n"
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = {
            node: pool.submit(_run_node, ssm, instance_id, _script(node), _SSM_COMMAND_TIMEOUT_S)
            for node, instance_id in zip(("A", "B"), instance_ids)
        }
        results = {node: _node_result(future.result(), node) for node, future in futures.items()}

    node_a, node_b = results["A"], results["B"]

    # ---- the mount is really NFS, on both nodes ----
    for node, result in results.items():
        assert result["fstype"] == "nfs4", (
            f"node {node} mounted {_MOUNT_POINT} as {result['fstype']!r}, not 'nfs4' -- a tmpfs "
            f"or a bind mount would satisfy every later assertion for the wrong reason"
        )
        assert result["fstype_magic"] == "nfs", (
            f"node {node}'s statfs magic reports {result['fstype_magic']!r}, expected 'nfs'"
        )
        assert result["f_bsize"] == 1048576, (
            f"node {node}'s statvfs f_bsize is {result['f_bsize']!r}, expected EFS's 1048576"
        )

    # ---- single-writer O_APPEND is lossless ----
    assert node_b["own_a_len"] == _RECORDS_PER_NODE * _RECORD_SIZE, (
        f"node A's own append log is {node_b['own_a_len']} bytes as read from node B, expected "
        f"{_RECORDS_PER_NODE * _RECORD_SIZE} -- a single writer's O_APPEND must lose nothing"
    )
    assert node_b["own_a_all_valid"] is True, (
        "node A's own append log contains a record whose embedded sha256 does not match its body"
    )
    assert node_b["own_a_tags_a"] == _RECORDS_PER_NODE, (
        f"node A's own append log holds {node_b['own_a_tags_a']} A-tagged records, expected "
        f"{_RECORDS_PER_NODE}"
    )

    # ---- concurrent O_APPEND from two clients never tears a record ----
    # Deliberately NOT an equality on the length: the Linux NFS client computes the append offset
    # client-side, so two nodes may legally collide on one offset. Torn bytes are the thing no
    # object store can avoid and no faithful NFS server produces.
    assert node_b["shared_len"] % _RECORD_SIZE == 0, (
        f"the two-node append log is {node_b['shared_len']} bytes, which is not a multiple of "
        f"{_RECORD_SIZE} -- a partial record was written"
    )
    assert node_b["shared_all_valid"] is True, (
        f"the two-node append log has {node_b['shared_records']} records and at least one fails "
        f"its embedded sha256 -- concurrent 512-byte appends were torn or interleaved"
    )
    assert node_b["shared_tags"] == ["A", "B"], (
        f"the two-node append log carries tags {node_b['shared_tags']!r}, expected both nodes' "
        f"records to be present"
    )
    assert node_b["shared_len"] <= 2 * _RECORDS_PER_NODE * _RECORD_SIZE, (
        f"the two-node append log is {node_b['shared_len']} bytes, more than the "
        f"{2 * _RECORDS_PER_NODE * _RECORD_SIZE} bytes the two nodes wrote"
    )

    # ---- close-to-open consistency across two clients ----
    assert node_b["live_before_sha"] == node_b["v1_sha"], (
        f"node B's first open() of `live` returned sha256 {node_b['live_before_sha']!r}, expected "
        f"node A's fsync'd-and-closed content {node_b['v1_sha']!r}"
    )

    # ---- hard links: one inode, two names, observed by the node that created neither ----
    assert node_b["same_inode"] is True, (
        "node B sees different st_ino for hl/a and hl/b -- a hard link must be one inode"
    )
    assert (node_b["nlink_a"], node_b["nlink_b"]) == (2, 2), (
        f"node B sees st_nlink {(node_b['nlink_a'], node_b['nlink_b'])!r} for the two names of "
        f"one inode, expected (2, 2)"
    )
    assert node_b["a_gone"] is True, "hl/a is still present after node A unlinked it"
    assert node_b["nlink_b_after"] == 1, (
        f"after unlinking one of two names node B sees st_nlink {node_b['nlink_b_after']!r}, "
        f"expected 1"
    )
    assert node_b["b_sha_after"] == node_b["linked_sha"], (
        f"after unlinking hl/a the surviving hl/b reads sha256 {node_b['b_sha_after']!r}, "
        f"expected the original {node_b['linked_sha']!r} -- unlinking one name must not destroy "
        f"the data"
    )

    # ---- rename is atomic as observed from the other node ----
    assert node_b["rename_errors"] == [], (
        f"node B's reader saw errno(s) {node_b['rename_errors']!r} while node A renamed over "
        f"`live`; an atomic RENAME never exposes the target as absent"
    )
    assert set(node_b["rename_seen"]) <= {node_b["v1_sha"], node_b["v2_sha"]}, (
        f"node B observed contents {node_b['rename_seen']!r} for `live`, which includes a value "
        f"that is neither the pre-rename nor the post-rename content -- a copy-then-delete "
        f"rename exposes a short read"
    )
    assert node_b["live_after_sha"] == node_b["v2_sha"], (
        f"after node A's rename, node B reads sha256 {node_b['live_after_sha']!r} from `live`, "
        f"expected the renamed-in content {node_b['v2_sha']!r}"
    )

    # ---- the refusal: rmdir on a non-empty directory, from the node that did not fill it ----
    assert node_b["rmdir_errno"] == "ENOTEMPTY", (
        f"node B's rmdir of a directory holding one file reported {node_b['rmdir_errno']!r}, "
        f"expected 'ENOTEMPTY'"
    )
    # effect-absent
    assert node_b["ne_still_there"] is True, (
        "the directory node B failed to rmdir is gone anyway -- the refusal was not honoured"
    )
    assert node_b["ne_occupant"] == "occupant", (
        f"the file inside the un-removable directory reads {node_b['ne_occupant']!r}, expected "
        f"'occupant' -- the refused rmdir must change nothing"
    )
    # positive control, same directory, same mount, from node A once the occupant is gone
    assert node_a["rmdir_after_clear"] == "ok", (
        f"node A could not rmdir the directory after it was emptied: "
        f"{node_a['rmdir_after_clear']!r}"
    )
    assert node_a["ne_present_after_rmdir"] is False, (
        "the directory still exists after a successful rmdir"
    )

    # ---- the control plane was green throughout and said nothing about any of the above ----
    described = efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]
    assert described["LifeCycleState"] == "available", (
        f"DescribeFileSystems reports {described['LifeCycleState']!r} after the data-plane run"
    )
    assert described["NumberOfMountTargets"] == 2, (
        f"DescribeFileSystems reports {described['NumberOfMountTargets']!r} mount targets, "
        f"expected 2"
    )

    # ---- verified teardown, INLINE, inside the check's own budget ----
    # MEASURED, and the reason this block exists rather than relying on the registered cleanups:
    # `simparity.behavioral.harness.DEFAULT_CLEANUP_TIMEOUT_S` is 60.0 and bounds the WHOLE LIFO
    # chain on a daemon thread. Terminating two instances and waiting out two mount-target
    # deletions alone exceeds that, so the chain was abandoned mid-way and the filesystem, the
    # security group and the role were left behind on three consecutive runs -- with the check
    # reporting PASS, because a bounded cleanup never affects the verdict. Deleting here, before
    # the check returns, puts the teardown under the check's own (1800 s) budget. The registered
    # cleanups stay as the failure-path net; each returns immediately on a NotFound, so after this
    # block they are fast no-ops.
    _delete_instances_verified(ec2, instance_ids)
    for mount_target in efs.describe_mount_targets(FileSystemId=fs_id)["MountTargets"]:
        _delete_mt_verified(efs, mount_target["MountTargetId"])
    _delete_fs_verified(efs, fs_id)
    _delete_sg_verified(ec2, sg_id)
    _delete_role_verified(iam, role_name)
    assert efs.describe_file_systems(CreationToken=token)["FileSystems"] == [], (
        f"the filesystem created under token {token!r} is still listed after a verified delete"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
