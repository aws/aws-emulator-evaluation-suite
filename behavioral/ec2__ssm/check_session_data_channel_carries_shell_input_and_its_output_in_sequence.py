"""session-data-channel-carries-shell-input-and-its-output-in-sequence."""

from __future__ import annotations

import hashlib
import json
import ssl
import struct
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-data-channel-carries-shell-input-and-its-output-in-sequence"
GROUP = "session-data-channel"
SERVICES = ["ec2", "ssm"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE = "t3.nano"
#: Session Manager data channel framing: a 116-byte header, then the payload length and payload.
_HEADER_LENGTH = 116
_OUTPUT, _SIZE = 1, 3


def _teardown(undo, *gone):
    """A cleanup that runs ``undo()`` and raises on failure unless the error says it is gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in gone:
                return
            raise

    return run_undo


def _budget(ctx, cap_s):
    left = ctx.time_left()
    return cap_s if left is None else max(5.0, min(cap_s, left - 30.0))


def _managed_instance(ctx):
    """A t3.nano Amazon Linux instance whose profile carries the SSM core policy, once Online."""
    ec2, ssm, iam = ctx.client("ec2"), ctx.client("ssm"), ctx.client("iam")
    name = ctx.unique_name("sim2real-sdc-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS)
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=_CORE_POLICY)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name,
                                                            PolicyArn=_CORE_POLICY),
                             "NoSuchEntity"))
    iam.create_instance_profile(InstanceProfileName=name, Tags=_TAGS)
    ctx.on_cleanup(_teardown(lambda: iam.delete_instance_profile(InstanceProfileName=name),
                             "NoSuchEntity"))
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    ctx.on_cleanup(_teardown(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=name, RoleName=name), "NoSuchEntity"))

    image = ssm.get_parameter(Name=_AMI_PARAMETER)["Parameter"]["Value"]
    assert image.startswith("ami-"), f"the public AMI parameter must hold an image id; got {image!r}"
    net = ctx.network()
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    zones = [z for z in net.availability_zones if z in offered]
    assert zones, f"no zone of {net.availability_zones!r} offers {_INSTANCE_TYPE}"

    # A new instance profile is not usable by RunInstances until IAM has propagated it.
    deadline = time.monotonic() + _budget(ctx, 120.0)
    while True:
        try:
            instance_id = ec2.run_instances(
                ImageId=image, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
                SubnetId=net.subnets[zones[0]], IamInstanceProfile={"Name": name},
                MetadataOptions={"HttpTokens": "required"},
                TagSpecifications=[{"ResourceType": "instance", "Tags": _TAGS}],
            )["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValue" or (
                    time.monotonic() > deadline):
                raise
            time.sleep(5)

    def terminate(iid=instance_id):
        ec2.terminate_instances(InstanceIds=[iid])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[iid], WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    ctx.on_cleanup(_teardown(terminate, "InvalidInstanceID.NotFound"))

    deadline = time.monotonic() + _budget(ctx, 600.0)
    info = []
    while time.monotonic() < deadline:
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])["InstanceInformationList"]
        if info and info[0].get("PingStatus") == "Online":
            return instance_id
        time.sleep(5)
    raise AssertionError(f"the instance never reported Online to Systems Manager: {info!r}")


def _shell_document(ctx):
    """A Standard_Stream session document of the check's own, so account preferences never apply."""
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-sdc-shell-")
    content = {"schemaVersion": "1.0", "description": "Interactive shell",
               "sessionType": "Standard_Stream",
               "inputs": {"runAsEnabled": False, "idleSessionTimeout": "20",
                          "shellProfile": {"linux": "", "windows": ""}}}
    ssm.create_document(Name=name, DocumentType="Session", DocumentFormat="JSON",
                        Content=json.dumps(content), Tags=_TAGS)
    ctx.on_cleanup(_teardown(lambda: ssm.delete_document(Name=name), "InvalidDocument"))
    return name


def _start_session(ctx, instance_id, document):
    ssm = ctx.client("ssm")
    # An instance reported Online can still be opening its messaging channel for a moment.
    deadline = time.monotonic() + _budget(ctx, 120.0)
    while True:
        try:
            started = ssm.start_session(Target=instance_id, DocumentName=document)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TargetNotConnected" or (
                    time.monotonic() > deadline):
                raise
            time.sleep(5)
    # A session already ended answers ValidationException, which is the state the cleanup wants.
    ctx.on_cleanup(_teardown(lambda sid=started["SessionId"]: ssm.terminate_session(SessionId=sid),
                             "ValidationException", "DoesNotExistException"))
    return started


def _encode(message_type, sequence, payload_type, payload, flags=0):
    message_id = uuid.uuid4().bytes
    return b"".join([
        struct.pack(">I", _HEADER_LENGTH), message_type.encode().ljust(32, b" "),
        struct.pack(">IQqQ", 1, int(time.time() * 1000), sequence, flags),
        # The message id is written least-significant half first.
        message_id[8:], message_id[:8], hashlib.sha256(payload).digest(),
        struct.pack(">II", payload_type, len(payload)), payload,
    ])


def _decode(frame):
    header = struct.unpack(">I", frame[:4])[0]
    payload_type, length = struct.unpack(">II", frame[header - 4:header + 4])
    return {
        "type": frame[4:36].strip(b"\x00 ").decode(),
        "seq": struct.unpack(">q", frame[48:56])[0],
        "id": str(uuid.UUID(bytes=frame[72:80] + frame[64:72])),
        "payload_type": payload_type,
        "payload": frame[header + 4:header + 4 + length],
    }


class _DataChannel:
    """A client of one session's data channel, speaking the Session Manager framing."""

    def __init__(self, ctx, stream_url, token):
        import websocket

        verify = ctx.http_verify
        sslopt = ({"cert_reqs": ssl.CERT_NONE} if verify is False
                  else {"ca_certs": verify} if isinstance(verify, str) else {})
        self.ws = websocket.create_connection(ctx.endpoint_url(stream_url, websocket=True),
                                              timeout=5, sslopt=sslopt)
        self.ws.send(json.dumps({
            "MessageSchemaVersion": "1.0", "RequestId": str(uuid.uuid4()), "TokenValue": token,
            "ClientId": str(uuid.uuid4()), "ClientVersion": "1.2.0.0"}))
        self.sent = 0
        self.output = {}
        self.messages = []
        self.close_frame = None

    def send_input(self, data):
        self.ws.send_binary(_encode("input_stream_data", self.sent, _OUTPUT, data))
        self.sent += 1

    def poll(self):
        """Read one frame, acknowledging shell output; False once the server closed the socket."""
        import websocket

        try:
            opcode, data = self.ws.recv_data(control_frame=True)
        except websocket.WebSocketTimeoutException:
            return True
        except websocket.WebSocketConnectionClosedException:
            return False
        if opcode == websocket.ABNF.OPCODE_CLOSE:
            code = struct.unpack(">H", data[:2])[0] if len(data) >= 2 else None
            self.close_frame = (code, data[2:].decode(errors="replace"))
            return False
        if opcode != websocket.ABNF.OPCODE_BINARY:
            return True
        message = _decode(data)
        self.messages.append(message)
        if message["type"] == "output_stream_data":
            self.output.setdefault(message["seq"], message["payload"])
            ack = {"AcknowledgedMessageType": message["type"],
                   "AcknowledgedMessageId": message["id"],
                   "AcknowledgedMessageSequenceNumber": message["seq"],
                   "IsSequentialMessage": True}
            self.ws.send_binary(_encode("acknowledge", 0, 0, json.dumps(ack).encode(), flags=3))
        return True

    def text(self):
        return b"".join(self.output[s] for s in sorted(self.output)).decode(errors="replace")

    def until(self, ctx, predicate, what, cap_s=60.0):
        deadline = time.monotonic() + _budget(ctx, cap_s)
        while time.monotonic() < deadline:
            if predicate(self):
                return
            if not self.poll():
                break
        assert predicate(self), (
            f"{what} never happened; close frame {self.close_frame!r}, message types "
            f"{[m['type'] for m in self.messages]!r}, output {self.text()[-300:]!r}"
        )

    def close(self):
        try:
            self.ws.close()
        except OSError:
            pass


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The StreamUrl StartSession returns, opened with its TokenValue, carries keystrokes to a shell
    on the instance and the shell's computed output back, every frame in sequence and acknowledged.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_StartSession.html
    """
    instance_id = _managed_instance(ctx)
    started = _start_session(ctx, instance_id, _shell_document(ctx))
    channel = _DataChannel(ctx, started["StreamUrl"], started["TokenValue"])
    ctx.on_cleanup(channel.close)

    channel.until(ctx, lambda c: c.text().rstrip().endswith("$"), "a shell prompt on the channel")
    marker = ctx.unique_name("m").replace("-", "")
    channel.send_input(f"echo $((6*7))-{marker}\r".encode())
    channel.until(ctx, lambda c: f"42-{marker}" in c.text(), "the shell's answer to the input")

    acks = [json.loads(m["payload"]) for m in channel.messages if m["type"] == "acknowledge"]
    assert {(a.get("AcknowledgedMessageType"), a.get("AcknowledgedMessageSequenceNumber"))
            for a in acks} >= {("input_stream_data", 0)}, (
        f"the input frame (sequence 0) must be acknowledged; acknowledgements were {acks!r}"
    )
    assert f"$((6*7))-{marker}" in channel.text(), (
        f"the terminal echoes the typed command; output was {channel.text()[-300:]!r}"
    )
    sequences = sorted(channel.output)
    assert sequences == list(range(len(sequences))), (
        f"shell output frames are numbered from 0 without gaps; got {sequences!r}"
    )
    kinds = {m["payload_type"] for m in channel.messages if m["type"] == "output_stream_data"}
    assert kinds == {_OUTPUT}, f"shell output travels as Output payloads; got types {kinds!r}"
    assert channel.close_frame is None, (
        f"the channel stays open while the shell runs; it closed with {channel.close_frame!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
