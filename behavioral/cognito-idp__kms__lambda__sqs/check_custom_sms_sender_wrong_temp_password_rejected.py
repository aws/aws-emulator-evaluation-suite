"""custom-sms-sender-wrong-temp-password-rejected."""
from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-sms-sender-wrong-temp-password-rejected"
GROUP = "custom-sender-triggers"
SERVICES = ["cognito-idp", "kms", "lambda", "sqs"]

PHONE = "+15555550124"


def _wrong_code(code: str) -> str:
    """A string of the same shape as the real one that differs from it in every digit."""
    return "".join(str((int(c) + 5) % 10) if c.isdigit() else chr(((ord(c) - 33 + 1) % 94) + 33)
                   for c in code)


@tags("axis:rejection", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data",
     "cap:c3")
def run(ctx) -> None:
    """A temporary password that differs from the CustomSMSSender-decrypted one is rejected and
    leaves the user FORCE_CHANGE_PASSWORD; the real decrypted temporary password still signs in.
    """
    cog = ctx.client("cognito-idp")
    estate = _deploy_sms_estate(ctx)
    pool_id, client_id = estate["pool_id"], estate["client_id"]

    username = ctx.unique_name("sim2real-xsvc-user-")
    cog.admin_create_user(
        UserPoolId=pool_id, Username=username,
        UserAttributes=[{"Name": "phone_number", "Value": PHONE},
                        {"Name": "phone_number_verified", "Value": "true"}],
        DesiredDeliveryMediums=["SMS"],
    )
    ctx.on_cleanup(lambda: cog.admin_delete_user(UserPoolId=pool_id, Username=username))

    delivered = estate["inbox"].next_code(username, "CustomSMSSender_AdminCreateUser")
    code = delivered["code"]
    assert code, "the trigger decrypted an empty temporary password"
    wrong = _wrong_code(code)
    assert wrong != code, f"the mutated password {wrong!r} coincides with the real one {code!r}"

    refused = _refusal(lambda: cog.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": wrong},
    ))
    assert refused == ("NotAuthorizedException", "Incorrect username or password."), (
        f"signing in with a wrong temporary password was refused with {refused!r}"
    )

    still = cog.admin_get_user(UserPoolId=pool_id, Username=username)
    assert still["UserStatus"] == "FORCE_CHANGE_PASSWORD", (
        f"the rejected sign-in changed UserStatus to {still['UserStatus']!r}, expected it to "
        f"stay FORCE_CHANGE_PASSWORD"
    )

    challenge = cog.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": code},
    )
    assert challenge.get("ChallengeName") == "NEW_PASSWORD_REQUIRED", (
        f"signing in with the real decrypted temporary password gave challenge "
        f"{challenge.get('ChallengeName')!r}, expected NEW_PASSWORD_REQUIRED"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"

# Node.js: its Lambda runtime ships both the AWS SDK v3 and `node:crypto` (HKDF + AES-GCM), so
# the AWS Encryption SDK message Cognito hands over in `request.code` can be parsed and
# decrypted with NO packaged dependency. The function KMS-decrypts the data key under the
# message's own encryption context, derives the content key the way the ESDK algorithm suite
# says, authenticates the header, decrypts every frame and ships the plaintext code to SQS. A
# decryption failure is shipped too (ok=false), so the check fails naming it instead of timing
# out on an empty queue.
_SENDER_JS = r"""
import { KMSClient, DecryptCommand } from "@aws-sdk/client-kms";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import crypto from "node:crypto";

const kms = new KMSClient({});
const sqs = new SQSClient({});

const SUITES = {
  0x0014: [16, null, false], 0x0046: [24, null, false], 0x0078: [32, null, false],
  0x0114: [16, "sha256", false], 0x0146: [24, "sha256", false], 0x0178: [32, "sha256", false],
  0x0214: [16, "sha256", false], 0x0346: [24, "sha384", false], 0x0378: [32, "sha384", false],
  0x0478: [32, "sha512", true], 0x0578: [32, "sha512", true],
};

async function retryDenied(fn) {
  let last;
  for (let i = 0; i < 25; i++) {
    try { return await fn(); } catch (e) {
      if (!String(e && e.name).includes("AccessDenied")) throw e;
      last = e; await new Promise(r => setTimeout(r, 1000));
    }
  }
  throw last;
}

function gcmDecrypt(alg, key, iv, aad, ct, tag) {
  const d = crypto.createDecipheriv(alg, key, iv, { authTagLength: 16 });
  d.setAAD(aad); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

async function decryptCode(b64) {
  const buf = Buffer.from(b64, "base64");
  let off = 0;
  const u8 = () => buf.readUInt8(off++);
  const u16 = () => { const v = buf.readUInt16BE(off); off += 2; return v; };
  const u32 = () => { const v = buf.readUInt32BE(off); off += 4; return v; };
  const u64 = () => { const v = Number(buf.readBigUInt64BE(off)); off += 8; return v; };
  const take = n => { const v = buf.subarray(off, off + n); off += n; return v; };

  const version = u8();
  if (version === 0x01) { const t = u8(); if (t !== 0x80) throw new Error("bad v1 type " + t); }
  else if (version !== 0x02) throw new Error("unknown ESDK message version " + version);
  const suiteId = u16();
  const suite = SUITES[suiteId];
  if (!suite) throw new Error("unsupported algorithm suite 0x" + suiteId.toString(16));
  const [keyLen, digest, committing] = suite;
  const messageId = take(version === 0x01 ? 16 : 32);
  const aadLen = u16();
  const ec = {};
  if (aadLen > 0) {
    const pairs = u16();
    for (let i = 0; i < pairs; i++) {
      const k = take(u16()).toString("utf8"); ec[k] = take(u16()).toString("utf8");
    }
  }
  const edks = [];
  const edkCount = u16();
  for (let i = 0; i < edkCount; i++) {
    edks.push({ provider: take(u16()).toString("utf8"), info: take(u16()).toString("utf8"),
                blob: Buffer.from(take(u16())) });
  }
  const contentType = u8();
  let ivLen = 12, frameLen, commitment = null;
  if (version === 0x01) { take(4); ivLen = u8(); frameLen = u32(); }
  else { frameLen = u32(); commitment = take(32); }
  const headerBody = buf.subarray(0, off);
  const headerIv = version === 0x01 ? take(ivLen) : Buffer.alloc(12);
  const headerTag = take(16);

  const edk = edks.find(e => e.provider === "aws-kms");
  if (!edk) throw new Error("no aws-kms encrypted data key in " + JSON.stringify(edks.map(e => e.provider)));
  const dk = await retryDenied(() => kms.send(new DecryptCommand({
    CiphertextBlob: edk.blob, EncryptionContext: ec, KeyId: edk.info })));
  const dataKey = Buffer.from(dk.Plaintext);

  let key;
  const sid = Buffer.alloc(2); sid.writeUInt16BE(suiteId);
  if (committing) {
    key = Buffer.from(crypto.hkdfSync(digest, dataKey, messageId,
                                      Buffer.concat([sid, Buffer.from("DERIVEKEY")]), keyLen));
    const ck = Buffer.from(crypto.hkdfSync(digest, dataKey, messageId, Buffer.from("COMMITKEY"), 32));
    if (!crypto.timingSafeEqual(ck, commitment)) throw new Error("key commitment mismatch");
  } else if (digest) {
    key = Buffer.from(crypto.hkdfSync(digest, dataKey, Buffer.alloc(0),
                                      Buffer.concat([sid, messageId]), keyLen));
  } else {
    key = dataKey;
  }
  const alg = "aes-" + (keyLen * 8) + "-gcm";
  gcmDecrypt(alg, key, headerIv, headerBody, Buffer.alloc(0), headerTag);

  const aadFor = (label, seq, len) => {
    const s = Buffer.alloc(4); s.writeUInt32BE(seq);
    const l = Buffer.alloc(8); l.writeBigUInt64BE(BigInt(len));
    return Buffer.concat([messageId, Buffer.from(label), s, l]);
  };
  const parts = [];
  if (contentType === 0x02) {
    for (;;) {
      let seq = u32();
      if (seq === 0xFFFFFFFF) {
        seq = u32(); const iv = take(ivLen); const len = u32(); const ct = take(len); const tag = take(16);
        parts.push(gcmDecrypt(alg, key, iv, aadFor("AWSKMSEncryptionClient Final Frame", seq, len), ct, tag));
        break;
      }
      const iv = take(ivLen); const ct = take(frameLen); const tag = take(16);
      parts.push(gcmDecrypt(alg, key, iv, aadFor("AWSKMSEncryptionClient Frame", seq, frameLen), ct, tag));
    }
  } else if (contentType === 0x01) {
    const iv = take(ivLen); const len = u64(); const ct = take(len); const tag = take(16);
    parts.push(gcmDecrypt(alg, key, iv, aadFor("AWSKMSEncryptionClient Single Block", 1, len), ct, tag));
  } else {
    throw new Error("unknown content type " + contentType);
  }
  return { code: Buffer.concat(parts).toString("utf8"), version, suite: suiteId,
           keyArn: edk.info, ecKeys: Object.keys(ec).sort() };
}

export const handler = async (event) => {
  const req = event.request || {};
  const out = { triggerSource: event.triggerSource, userName: event.userName,
                userPoolId: event.userPoolId, type: req.type || null,
                phoneNumber: (req.userAttributes || {}).phone_number || null,
                clientMetadata: req.clientMetadata || null, receivedAt: Date.now() };
  try { Object.assign(out, await decryptCode(req.code)); out.ok = true; }
  catch (e) { out.ok = false; out.error = String((e && e.stack) || e); }
  await retryDenied(() => sqs.send(new SendMessageCommand({
    QueueUrl: process.env.SIM2REAL_QUEUE_URL, MessageBody: JSON.stringify(out) })));
};
"""


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _refusal(fn) -> tuple[str, str]:
    """Return the (code, message) of a call expected to be REJECTED.

    Raises when the call SUCCEEDS instead, naming what came back."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, which is the defect: {result!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(ctx, probe, predicate, *, timeout_s=90.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as e:
        teardown_code = e.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchEntity",):
            raise RuntimeError(f"IAM role {role_name} could not be deleted: {e!r}") from e


class _CodeInbox:
    """Drains the trigger's SQS sink and hands back the decrypted code for one delivery."""

    def __init__(self, ctx, sqs, queue_url: str):
        self.ctx, self.sqs, self.queue_url, self.seen = ctx, sqs, queue_url, []

    def next_code(self, username: str, trigger_source: str, timeout_s: float = 120.0) -> dict:
        timeout_s = _budget_s(self.ctx, timeout_s)
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            for i, m in enumerate(self.seen):
                if m.get("userName") == username and m.get("triggerSource") == trigger_source:
                    self.seen.pop(i)
                    assert m.get("ok") is True, (
                        f"the CustomSMSSender trigger could not decrypt request.code: "
                        f"{m.get('error')!r}"
                    )
                    return m
            resp = self.sqs.receive_message(QueueUrl=self.queue_url, MaxNumberOfMessages=10,
                                            WaitTimeSeconds=5)
            for raw in resp.get("Messages", []):
                self.seen.append(json.loads(raw["Body"]))
                self.sqs.delete_message(QueueUrl=self.queue_url,
                                        ReceiptHandle=raw["ReceiptHandle"])
        raise TimeoutError(
            f"no {trigger_source!r} code for {username!r} reached the trigger's queue within "
            f"{timeout_s}s; deliveries seen but unmatched: {self.seen!r}"
        )


def _deploy_sms_estate(ctx) -> dict:
    """KMS key + SQS sink + execution role + CustomSMSSender Lambda + user pool + app client.

    Every create registers its teardown immediately. The Lambda role has NO logs permissions,
    so the function can never create /aws/lambda/<fn> and no log group can be stranded."""
    sts = ctx.client("sts")
    kms = ctx.client("kms")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    cog = ctx.client("cognito-idp")
    ident = sts.get_caller_identity()
    account = ident["Account"]
    partition = ident["Arn"].split(":")[1]

    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AccountRoot", "Effect": "Allow",
             "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
             "Action": "kms:*", "Resource": "*"},
            {"Sid": "CognitoEncryptsCodes", "Effect": "Allow",
             "Principal": {"Service": "cognito-idp.amazonaws.com"},
             "Action": ["kms:Encrypt", "kms:CreateGrant"], "Resource": "*",
             "Condition": {"StringEquals": {"aws:SourceAccount": account}}},
        ],
    }
    key_arn = kms.create_key(
        Description=f"{_XSVC_PREFIX}cognito custom sms sender code key",
        KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT",
        Policy=json.dumps(key_policy),
        Tags=[{"TagKey": t["Key"], "TagValue": t["Value"]} for t in _xsvc_tags_kv()],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name(f"{_XSVC_PREFIX}codes-"),
        tags={t["Key"]: t["Value"] for t in _xsvc_tags_kv()},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_name = ctx.unique_name(f"{_XSVC_PREFIX}role-sender-")
    trust = {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                               Path="/sim2real/", Tags=_xsvc_tags_kv())["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key_arn},
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
        ]}))

    fn_name = ctx.unique_name(f"{_XSVC_PREFIX}fn-sender-")
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.mjs", _SENDER_JS)
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            fn_arn = lam.create_function(
                FunctionName=fn_name, Runtime="nodejs22.x", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": zip_buf.getvalue()},
                Timeout=60, MemorySize=256,
                Environment={"Variables": {"SIM2REAL_QUEUE_URL": queue_url}},
                Tags={t["Key"]: t["Value"] for t in _xsvc_tags_kv()},
            )["FunctionArn"]
            break
        except ClientError as e:
            if "cannot be assumed" not in str(e):
                raise
            if time.monotonic() > deadline:
                raise TimeoutError(f"Lambda {fn_name} execution role never became assumable") from e
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(ctx, lambda: lam.get_function_configuration(FunctionName=fn_name),
                lambda r: r.get("State") == "Active", timeout_s=90, interval_s=2.0,
                description=f"Lambda {fn_name} Active")

    pool = cog.create_user_pool(
        PoolName=ctx.unique_name(f"{_XSVC_PREFIX}pool-"),
        LambdaConfig={"CustomSMSSender": {"LambdaVersion": "V1_0", "LambdaArn": fn_arn},
                      "KMSKeyID": key_arn},
        UserPoolTags={_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")},
    )["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda: cog.delete_user_pool(UserPoolId=pool_id))
    lam.add_permission(FunctionName=fn_name, StatementId="cognito-custom-sms-sender",
                       Action="lambda:InvokeFunction", Principal="cognito-idp.amazonaws.com",
                       SourceArn=pool_arn)

    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name(f"{_XSVC_PREFIX}client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cog.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    return {"pool_id": pool_id, "client_id": client_id, "key_arn": key_arn,
            "fn_arn": fn_arn, "inbox": _CodeInbox(ctx, sqs, queue_url)}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
