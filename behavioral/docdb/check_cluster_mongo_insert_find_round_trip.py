"""cluster-mongo-insert-find-round-trip."""
from __future__ import annotations

import io
import json
import secrets
import string
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-mongo-insert-find-round-trip"
GROUP = "cluster-instance"
SERVICES = ["docdb"]

_INSTANCE_CLASS = "db.t3.medium"
_MONGO_PORT = 27017
_ADMIN_USER = "dbadmin"

# Marks a failure as a native data-plane failure. The message interpolates the socket error the
# probe caught, so without the marker the one verdict this check exists to produce -- the
# advertised endpoint speaks nothing -- would read as a client-side environment problem.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_RESOURCE_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": CHECK},
]


def _admin_password() -> str:
    """A fresh password meeting DocDB's constraints (8-100 printable ASCII, no / " @)."""
    alphabet = string.ascii_letters + string.digits
    return "Sim2Real" + "".join(secrets.choice(alphabet) for _ in range(12))


def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code


def _describe_one(fn, list_key, id_field, id_value, **extra):
    try:
        resp = fn(**{id_field: id_value}, **extra)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code") or ""
        if "NotFound" in code:
            return None
        raise
    items = resp.get(list_key, [])
    return items[0] if items else None


def _poll(probe, predicate, timeout_s=1800, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)


def _describe_cluster(docdb, cluster_id, **extra):
    return _describe_one(docdb.describe_db_clusters, "DBClusters", "DBClusterIdentifier", cluster_id, **extra)


def _describe_instance(docdb, instance_id, **extra):
    return _describe_one(docdb.describe_db_instances, "DBInstances", "DBInstanceIdentifier", instance_id, **extra)


def _delete_instance_and_wait(docdb, instance_id, timeout_s=1200, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            docdb.delete_db_instance(DBInstanceIdentifier=instance_id)
            break
        except ClientError as e:
            code = _fault_base(e.response.get("Error", {}).get("Code") or "")
            if code == "DBInstanceNotFound":
                return
            if code != "InvalidDBInstanceState" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    _poll(lambda: _describe_instance(docdb, instance_id), lambda i: i is None,
          timeout_s=timeout_s, interval_s=interval_s)


def _delete_cluster_and_wait(docdb, cluster_id, timeout_s=900, interval_s=10):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            docdb.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
            break
        except ClientError as e:
            code = _fault_base(e.response.get("Error", {}).get("Code") or "")
            if code == "DBClusterNotFound":
                return
            if code != "InvalidDBClusterState" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    _poll(lambda: _describe_cluster(docdb, cluster_id), lambda c: c is None,
          timeout_s=timeout_s, interval_s=interval_s)


def _cluster_scoped_security_group(ec2, ctx, net, probe, port):
    """A security group in the run's network allowing `port` from the in-VPC probe's group ONLY.

    A DocumentDB cluster is a private VPC resource and a world-open ingress rule on its port is
    exactly the misconfiguration this check should not be modelling.
    """
    group_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-docdbsg-"),
        Description="sim2real docdb mongo data-plane check (probe-scoped ingress)",
        VpcId=net.vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _RESOURCE_TAGS}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=group_id))
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "UserIdGroupPairs": [{"GroupId": probe["sg"], "Description": "in-VPC probe only"}],
        }],
    )
    return group_id


def _subnet_group(docdb, ctx, net):
    name = ctx.unique_name("sim2real-behav-docdbsng-")
    docdb.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real docdb mongo data-plane check",
        SubnetIds=net.subnet_ids[:2],
        Tags=_RESOURCE_TAGS,
    )
    ctx.on_cleanup(lambda: docdb.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:native", "plane:data")
def run(ctx) -> None:
    """A DocumentDB cluster's writer instance speaks the MongoDB wire protocol: a SCRAM-SHA-1
    authenticated session over TLS inserts a document and a find by _id returns the exact
    document back, over a connection admitted only from the run's own in-VPC probe.
    """
    docdb = ctx.client("docdb")
    ec2 = ctx.client("ec2")

    # Registered before the cluster, so LIFO teardown drops cluster resources first.
    net = ctx.network()
    probe = _probe_open(ctx, net)
    sg_id = _cluster_scoped_security_group(ec2, ctx, net, probe, _MONGO_PORT)
    subnet_group = _subnet_group(docdb, ctx, net)

    cluster_id = ctx.unique_name("sim2real-behav-docdb-cl-")
    admin_password = _admin_password()
    docdb.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="docdb",
        MasterUsername=_ADMIN_USER,
        MasterUserPassword=admin_password,
        DBSubnetGroupName=subnet_group,
        VpcSecurityGroupIds=[sg_id],
        BackupRetentionPeriod=1,
        StorageEncrypted=False,
        DeletionProtection=False,
        Tags=_RESOURCE_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(docdb, cluster_id))

    instance_id = ctx.unique_name("sim2real-behav-docdb-in-")
    docdb.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBClusterIdentifier=cluster_id,
        DBInstanceClass=_INSTANCE_CLASS,
        Engine="docdb",
        Tags=_RESOURCE_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance_and_wait(docdb, instance_id))

    instance = _poll(
        lambda: _describe_instance(docdb, instance_id),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
    )
    endpoint = instance.get("Endpoint") or {}
    host, port = endpoint.get("Address"), endpoint.get("Port")
    assert host, (
        f"an available DocumentDB instance advertised no Endpoint.Address: {instance!r}; "
        f"without an address there is no data plane to reach"
    )

    db_name, collection = "sim2real", "docs"
    doc_id = "sim2real-doc-" + ctx.unique_name("")
    doc_value = "sim2real-value-" + ctx.unique_name("")
    session = _probe_call(ctx, probe, host, port, {
        "username": _ADMIN_USER,
        "password": admin_password,
        "db": db_name,
        "collection": collection,
        "doc_id": doc_id,
        "doc_value": doc_value,
    })
    _probe_release(ctx, probe)

    if not session.get("ok") and str(session.get("error") or "").startswith("connect:"):
        raise AssertionError(
            f"{DATAPLANE_MARKER}: the instance endpoint {host}:{port} advertised in "
            f"DescribeDBInstances accepts no TCP connection from inside its own VPC "
            f"({session['error']}); an endpoint that cannot be connected to is not a data plane"
        )
    assert session.get("error") is None, (
        f"the mongo session failed: {session['error']!r}; replies so far: {session!r}"
    )
    assert session.get("authenticated") is True, (
        f"SCRAM-SHA-1 authentication against the writer instance never completed: {session!r}"
    )

    # ---- insert: the server actually durably wrote one document ---------------
    assert session.get("insert_ok") in (1, 1.0), f"insert command returned ok={session.get('insert_ok')!r}: {session!r}"
    assert session.get("insert_n") == 1, f"insert must report n=1, got {session.get('insert_n')!r}: {session!r}"
    assert not session.get("insert_write_errors"), f"insert reported writeErrors: {session['insert_write_errors']!r}"

    # ---- find: the exact document comes back, not a reshaped or partial one ---
    assert session.get("find_ok") in (1, 1.0), f"find command returned ok={session.get('find_ok')!r}: {session!r}"
    batch = session.get("first_batch")
    assert batch == [{"_id": doc_id, "value": doc_value}], (
        f"expected the find to return exactly [{{'_id': {doc_id!r}, 'value': {doc_value!r}}}], "
        f"got {batch!r}"
    )

    _delete_instance_and_wait(docdb, instance_id)
    _delete_cluster_and_wait(docdb, cluster_id)
    assert _describe_cluster(docdb, cluster_id) is None, f"{cluster_id} still resolves after delete"


# ===== the in-VPC mongo probe =====
#
# The cluster answers only inside its VPC, so the protocol round trip is carried there by a
# Lambda function in the run's network. The function has its own security group, and the
# cluster's group admits only that group. The handler drives sockets and BSON framing and
# reports what came back; every assertion lives in this file. It speaks the MongoDB wire
# protocol (OP_MSG, BSON, SCRAM-SHA-1) by hand, so it needs nothing beyond the Python standard
# library -- there is no Mongo client in the allowed dependency set.

_PROBE_SRC = r'''
import socket
import ssl
import struct
import hashlib
import hmac
import base64
import os


def _bson_encode_element(key, value):
    key_bytes = key.encode("utf-8") + b"\x00"
    if isinstance(value, bool):
        return b"\x08" + key_bytes + (b"\x01" if value else b"\x00")
    if isinstance(value, int):
        if -2**31 <= value < 2**31:
            return b"\x10" + key_bytes + struct.pack("<i", value)
        return b"\x12" + key_bytes + struct.pack("<q", value)
    if isinstance(value, float):
        return b"\x01" + key_bytes + struct.pack("<d", value)
    if isinstance(value, str):
        s = value.encode("utf-8") + b"\x00"
        return b"\x02" + key_bytes + struct.pack("<i", len(s)) + s
    if isinstance(value, bytes):
        return b"\x05" + key_bytes + struct.pack("<i", len(value)) + b"\x00" + value
    if isinstance(value, dict):
        return b"\x03" + key_bytes + _bson_encode_document(value)
    if isinstance(value, list):
        arr_doc = {str(i): v for i, v in enumerate(value)}
        return b"\x04" + key_bytes + _bson_encode_document(arr_doc)
    if value is None:
        return b"\x0A" + key_bytes
    raise TypeError("cannot BSON-encode %r" % (value,))


def _bson_encode_document(d):
    body = b"".join(_bson_encode_element(k, v) for k, v in d.items())
    total = 4 + len(body) + 1
    return struct.pack("<i", total) + body + b"\x00"


def _bson_decode_value(btype, buf, pos):
    if btype == 0x01:
        return struct.unpack_from("<d", buf, pos)[0], pos + 8
    if btype == 0x02:
        strlen = struct.unpack_from("<i", buf, pos)[0]
        pos += 4
        s = buf[pos:pos + strlen - 1].decode("utf-8")
        return s, pos + strlen
    if btype == 0x03:
        doc, end = _bson_decode_document(buf, pos)
        return doc, end
    if btype == 0x04:
        doc, end = _bson_decode_document(buf, pos)
        arr = [doc[str(i)] for i in range(len(doc))]
        return arr, end
    if btype == 0x05:
        ln = struct.unpack_from("<i", buf, pos)[0]
        pos += 4
        pos += 1  # subtype
        data = bytes(buf[pos:pos + ln])
        return data, pos + ln
    if btype == 0x07:
        return bytes(buf[pos:pos + 12]), pos + 12
    if btype == 0x08:
        return buf[pos] != 0, pos + 1
    if btype == 0x09:
        return struct.unpack_from("<q", buf, pos)[0], pos + 8
    if btype == 0x0A:
        return None, pos
    if btype == 0x10:
        return struct.unpack_from("<i", buf, pos)[0], pos + 4
    if btype == 0x11:
        return bytes(buf[pos:pos + 8]), pos + 8
    if btype == 0x12:
        return struct.unpack_from("<q", buf, pos)[0], pos + 8
    if btype == 0x13:
        return bytes(buf[pos:pos + 16]), pos + 16
    raise ValueError("unsupported BSON type 0x%02x at %d" % (btype, pos))


def _bson_decode_document(buf, offset=0):
    total = struct.unpack_from("<i", buf, offset)[0]
    end = offset + total
    pos = offset + 4
    result = {}
    while pos < end - 1:
        btype = buf[pos]
        pos += 1
        key_end = buf.index(b"\x00", pos)
        key = buf[pos:key_end].decode("utf-8")
        pos = key_end + 1
        value, pos = _bson_decode_value(btype, buf, pos)
        result[key] = value
    return result, end


def _build_op_msg(request_id, document):
    section = b"\x00" + _bson_encode_document(document)
    body = struct.pack("<I", 0) + section
    header = struct.pack("<iiii", 16 + len(body), request_id, 0, 2013)
    return header + body


def _recv_exact(sock, n):
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("the server closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_op_msg(sock):
    header = _recv_exact(sock, 16)
    length, _req_id, _resp_to, opcode = struct.unpack("<iiii", header)
    if opcode != 2013:
        raise ValueError("expected opCode 2013 (OP_MSG), got %r" % (opcode,))
    rest = _recv_exact(sock, length - 16)
    pos = 4  # skip flagBits
    result_doc = None
    while pos < len(rest):
        kind = rest[pos]
        pos += 1
        if kind == 0:
            result_doc, pos = _bson_decode_document(rest, pos)
        elif kind == 1:
            seq_len = struct.unpack_from("<i", rest, pos)[0]
            pos += seq_len
        else:
            break
    return result_doc


def _hmac_sha1(key, msg):
    return hmac.new(key, msg, hashlib.sha1).digest()


def _sha1(data):
    return hashlib.sha1(data).digest()


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


class MongoError(Exception):
    pass


def _scram_sha1_auth(send_command, username, password):
    client_nonce = base64.b64encode(os.urandom(18)).decode("ascii")
    client_first_bare = "n=%s,r=%s" % (username, client_nonce)
    client_first = "n,," + client_first_bare
    resp1 = send_command({
        "saslStart": 1,
        "mechanism": "SCRAM-SHA-1",
        "payload": client_first.encode("utf-8"),
        "autoAuthorize": 1,
        "$db": "admin",
    })
    if resp1.get("ok") not in (1, 1.0):
        raise MongoError("saslStart failed: %r" % (resp1,))
    conversation_id = resp1["conversationId"]
    server_first = resp1["payload"].decode("utf-8")
    parts = dict(p.split("=", 1) for p in server_first.split(","))
    r, s, i = parts["r"], parts["s"], int(parts["i"])
    if not r.startswith(client_nonce):
        raise MongoError("server nonce does not extend the client nonce: %r" % (server_first,))
    salt = base64.b64decode(s)
    hashed_password = hashlib.md5(("%s:mongo:%s" % (username, password)).encode("utf-8")).hexdigest().encode("utf-8")
    salted_password = hashlib.pbkdf2_hmac("sha1", hashed_password, salt, i, dklen=20)
    client_key = _hmac_sha1(salted_password, b"Client Key")
    stored_key = _sha1(client_key)
    client_final_no_proof = "c=biws,r=%s" % (r,)
    auth_message = "%s,%s,%s" % (client_first_bare, server_first, client_final_no_proof)
    client_signature = _hmac_sha1(stored_key, auth_message.encode("utf-8"))
    client_proof = _xor(client_key, client_signature)
    client_final = "%s,p=%s" % (client_final_no_proof, base64.b64encode(client_proof).decode("ascii"))
    resp2 = send_command({
        "saslContinue": 1,
        "conversationId": conversation_id,
        "payload": client_final.encode("utf-8"),
        "$db": "admin",
    })
    if resp2.get("ok") not in (1, 1.0):
        raise MongoError("saslContinue failed: %r" % (resp2,))
    server_key = _hmac_sha1(salted_password, b"Server Key")
    expected_server_signature = _hmac_sha1(server_key, auth_message.encode("utf-8"))
    server_final = resp2["payload"].decode("utf-8")
    sparts = dict(p.split("=", 1) for p in server_final.split(","))
    if base64.b64decode(sparts["v"]) != expected_server_signature:
        raise MongoError("server signature did not verify")
    if not resp2.get("done"):
        resp3 = send_command({
            "saslContinue": 1, "conversationId": conversation_id, "payload": b"", "$db": "admin",
        })
        if not resp3.get("done"):
            raise MongoError("authentication never reported done: %r" % (resp3,))


def _session(host, port, username, password, db_name, collection, doc_id, doc_value):
    out = {"ok": False, "error": None}
    try:
        sock = socket.create_connection((host, port), timeout=10)
    except Exception as exc:
        out["error"] = "connect: %s: %s" % (type(exc).__name__, exc)
        return out
    try:
        tls_ctx = ssl.create_default_context()
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = ssl.CERT_NONE
        tls_sock = tls_ctx.wrap_socket(sock, server_hostname=host)
    except Exception as exc:
        out["error"] = "tls: %s: %s" % (type(exc).__name__, exc)
        sock.close()
        return out
    state = {"req_id": 1}

    def send_command(doc):
        req_id = state["req_id"]
        state["req_id"] += 1
        tls_sock.sendall(_build_op_msg(req_id, doc))
        return _read_op_msg(tls_sock)

    try:
        _scram_sha1_auth(send_command, username, password)
        out["authenticated"] = True
        insert_resp = send_command({
            "insert": collection, "documents": [{"_id": doc_id, "value": doc_value}],
            "ordered": True, "$db": db_name,
        })
        out["insert_ok"] = insert_resp.get("ok")
        out["insert_n"] = insert_resp.get("n")
        out["insert_write_errors"] = insert_resp.get("writeErrors")
        find_resp = send_command({
            "find": collection, "filter": {"_id": doc_id}, "$db": db_name,
        })
        out["find_ok"] = find_resp.get("ok")
        out["first_batch"] = find_resp.get("cursor", {}).get("firstBatch")
        out["ok"] = True
    except MongoError as exc:
        out["error"] = "mongo: %s" % (exc,)
    except Exception as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        tls_sock.close()
    return out


def handler(event, context):
    return _session(
        event["host"], int(event["port"]), event["username"], event["password"],
        event["db"], event["collection"], event["doc_id"], event["doc_value"],
    )
'''

_LAMBDA_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)
_VPC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
_FN_TIMEOUT_S = 60
#: Bounded by this suite's 900s cleanup budget, not ENI release's full observed range.
_ENI_WAIT_S = 760


def _err(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _zip(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", src)
    return buf.getvalue()


def _probe_open(ctx, net) -> dict:
    """Deploy the probe into the run's network with its own security group.

    Returns ``{"fn": <function name>, "sg": <group id>}``; the cluster's group admits ``sg``.
    The teardown is registered before the first create. One subnet is enough to reach the whole
    VPC, and it keeps Lambda to one network interface.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-invpc-probe-")
    probe = {"fn": name, "role": name, "sg": None}
    ctx.on_cleanup(lambda: _probe_close(ctx, probe))
    probe["sg"] = ec2.create_security_group(
        GroupName=name,
        Description="sim2real in-VPC data-plane probe",
        VpcId=net.vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["GroupId"]
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST,
        Description="sim2real in-VPC data-plane probe",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=name, PolicyArn=_VPC_EXEC)
    # create_role returns before Lambda can assume the role, and no API reports when it can, so
    # the bounded retry sits on the first call that needs it.
    deadline = time.monotonic() + 180
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip(_PROBE_SRC)},
                Timeout=_FN_TIMEOUT_S,
                MemorySize=256,
                VpcConfig={"SubnetIds": net.subnet_ids[:1], "SecurityGroupIds": [probe["sg"]]},
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            if _err(exc) != "InvalidParameterValueException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    deadline = time.monotonic() + 600
    while (cfg := lam.get_function_configuration(FunctionName=name))["State"] == "Pending":
        assert time.monotonic() < deadline, f"probe function {name} never left Pending"
        time.sleep(5)
    assert cfg["State"] == "Active", f"probe function {name} is {cfg['State']!r}: {cfg.get('StateReason')!r}"
    return probe


def _probe_call(ctx, probe: dict, host: str, port: int, args: dict) -> dict:
    """Run one mongo session against ``host:port`` from inside the VPC.

    ``args`` carries ``username``, ``password``, ``db``, ``collection``, ``doc_id``,
    ``doc_value``; the result is the probe's own output dict (``ok``, ``error``,
    ``authenticated``, ``insert_ok``, ``insert_n``, ``find_ok``, ``first_batch``, ...). The
    function runs inside the VPC, so it dials the endpoint as published.
    """
    payload = {"host": host, "port": int(port), **args}
    lam = ctx.client("lambda", config=Config(read_timeout=_FN_TIMEOUT_S + 60))
    resp = lam.invoke(FunctionName=probe["fn"], Payload=json.dumps(payload).encode())
    out = json.loads(resp["Payload"].read())
    assert "FunctionError" not in resp, f"the in-VPC probe raised: {out!r}"
    return out


def _probe_release(ctx, probe: dict) -> None:
    """Delete the function once the session has run, so Lambda starts releasing its network
    interface while the rest of the check runs and tears down; ``_probe_close`` waits for it."""
    try:
        ctx.client("lambda").delete_function(FunctionName=probe["fn"])
    except ClientError as exc:
        if _err(exc) != "ResourceNotFoundException":
            raise


def _probe_close(ctx, probe: dict) -> None:
    """Delete the function, wait for its network interface to go, then its group, role and logs.

    Every step runs; the failures are raised together at the end.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    name, sg = probe["fn"], probe["sg"]

    def enis_gone():
        deadline, refused, enis = time.monotonic() + _ENI_WAIT_S, [], []
        while time.monotonic() < deadline:
            enis = ec2.describe_network_interfaces(Filters=[{"Name": "group-id", "Values": [sg]}])[
                "NetworkInterfaces"
            ]
            if not enis:
                return
            for eni in enis:
                if eni["Status"] == "available":
                    try:
                        ec2.delete_network_interface(NetworkInterfaceId=eni["NetworkInterfaceId"])
                    except ClientError as exc:
                        refused.append(f"{eni['NetworkInterfaceId']}: {_err(exc)}")
            time.sleep(15)
        raise AssertionError(
            f"interfaces still in {sg} after {_ENI_WAIT_S}s: "
            f"{[(e['NetworkInterfaceId'], e['Status']) for e in enis]}; refused deletes: {refused}"
        )

    def group_gone():
        deadline = time.monotonic() + 300
        while True:
            try:
                ec2.delete_security_group(GroupId=sg)
                return
            except ClientError as exc:
                if _err(exc) != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
            time.sleep(10)

    steps = [(f"function {name}", lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException")]
    if sg:
        steps += [(f"interfaces of {sg}", enis_gone, None), (f"security group {sg}", group_gone, "InvalidGroup.NotFound")]
    steps += [
        (f"policy of role {name}", lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_VPC_EXEC), "NoSuchEntity"),
        (f"role {name}", lambda: iam.delete_role(RoleName=name), "NoSuchEntity"),
        (
            f"log group of {name}",
            lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{name}"),
            "ResourceNotFoundException",
        ),
    ]
    failures = []
    for what, delete, gone in steps:
        try:
            delete()
        except ClientError as exc:
            if _err(exc) != gone:
                failures.append(f"{what}: {exc!r}")
        except Exception as exc:  # noqa: BLE001 - raised below, once every step was tried
            failures.append(f"{what}: {exc!r}")
    if failures:
        raise AssertionError(f"probe teardown left {len(failures)} resource(s): {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
