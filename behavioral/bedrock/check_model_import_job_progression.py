"""model-import-job-progression."""
from __future__ import annotations

import array
import json
import random
import struct
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "model-import-job-progression"
GROUP = "state-machine"
SERVICES = ["bedrock"]

# CreateModelImportJob validates structurally (architecture name, config/tensor-shape
# consistency, a fixed set of supported attention-head sizes, tokenizer presence) rather than
# model quality -- confirmed on real AWS: a tiny Llama checkpoint with head_size=4
# (hidden_size=16, num_attention_heads=4) is REJECTED with "does not support attention head
# size (4)... supported head size: [32, 64, 96, 128, 160, 192, 224, 256, 80, 112, 120]". A
# from-scratch checkpoint built to one of those head sizes therefore reaches Completed without
# needing a real pretrained model. The tokenizer is built the same way: a fast-tokenizer
# tokenizer.json (byte-fallback BPE over exactly vocab_size tokens) plus its config files,
# generated in-process so the check reaches no host other than the endpoint under test.
_TOKENIZER_SPECIALS = ("<unk>", "<s>", "</s>")

_MODEL_CONFIG = {
    "architectures": ["LlamaForCausalLM"],
    "model_type": "llama",
    "hidden_size": 64,
    "intermediate_size": 64,
    "num_hidden_layers": 1,
    "num_attention_heads": 2,
    "num_key_value_heads": 2,
    "vocab_size": 32000,
    "max_position_embeddings": 2048,
    "rms_norm_eps": 1e-06,
    "hidden_act": "silu",
    "torch_dtype": "float32",
    "bos_token_id": 0,
    "eos_token_id": 1,
    "tie_word_embeddings": False,
    "rope_theta": 10000.0,
    "attention_bias": False,
    "attention_dropout": 0.0,
    "initializer_range": 0.02,
    "use_cache": True,
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModelImportJob progresses to Completed and GetImportedModel reflects it."""
    bedrock = ctx.client("bedrock")
    s3_uri, role_arn = _stage_import_prereqs(ctx)

    job_name = ctx.unique_name("sim2real-modelimport-job-")
    imported_name = ctx.unique_name("sim2real-modelimport-model-")

    resp = _retry_transient(
        lambda: bedrock.create_model_import_job(
            jobName=job_name,
            importedModelName=imported_name,
            roleArn=role_arn,
            modelDataSource={"s3DataSource": {"s3Uri": s3_uri}},
            jobTags=[{"key": "sim2real-check", "value": CHECK}],
            importedModelTags=[{"key": "sim2real-check", "value": CHECK}],
        )
    )
    job_arn = resp["jobArn"]

    state = _poll_until(
        lambda: bedrock.get_model_import_job(jobIdentifier=job_arn),
        lambda r: r["status"] in ("Completed", "Failed"),
        timeout_s=_budget_s(ctx, 3600.0),
        ctx=ctx,
        interval_s=2.0,
    )
    assert state["status"] == "Completed", (
        f"import job ended in {state['status']!r}, expected 'Completed' "
        f"(failureMessage={state.get('failureMessage')!r})"
    )
    imported_model_arn = state["importedModelArn"]
    ctx.on_cleanup(lambda: _safe_delete_imported_model(bedrock, imported_model_arn))

    got = bedrock.get_imported_model(modelIdentifier=imported_model_arn)
    assert got["modelArn"] == imported_model_arn, (got["modelArn"], imported_model_arn)
    assert got["modelName"] == imported_name, (got["modelName"], imported_name)
    assert got["jobArn"] == job_arn, (got["jobArn"], job_arn)


def _stage_import_prereqs(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-import-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})

    def _cleanup_bucket() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)

    prefix = "model/"
    s3.put_object(Bucket=bucket, Key=f"{prefix}config.json", Body=json.dumps(_MODEL_CONFIG).encode("utf-8"))
    s3.put_object(Bucket=bucket, Key=f"{prefix}model.safetensors", Body=_build_llama_safetensors(_MODEL_CONFIG))
    for filename, body in _build_llama_tokenizer_files(_MODEL_CONFIG).items():
        s3.put_object(Bucket=bucket, Key=f"{prefix}{filename}", Body=body)

    role_arn = _create_bedrock_import_role(ctx, bucket)
    return f"s3://{bucket}/{prefix}", role_arn


def _build_llama_tokenizer_files(cfg: dict) -> dict[str, bytes]:
    """Build the tokenizer files for a byte-fallback BPE tokenizer.

    tokenizer.json, tokenizer_config.json and special_tokens_map.json; the vocabulary has
    exactly cfg["vocab_size"] entries: the three special tokens, the 256 byte tokens, the
    word-boundary marker, then filler pieces.
    """
    vocab_size = cfg["vocab_size"]
    pieces = list(_TOKENIZER_SPECIALS) + [f"<0x{b:02X}>" for b in range(256)] + ["\u2581"]
    pieces += [f"\u2581t{i}" for i in range(vocab_size - len(pieces))]
    assert len(pieces) == vocab_size, (len(pieces), vocab_size)
    unk, bos, eos = _TOKENIZER_SPECIALS
    tokenizer = {
        "version": "1.0",
        "truncation": None,
        "padding": None,
        "added_tokens": [
            {
                "id": i,
                "content": tok,
                "single_word": False,
                "lstrip": False,
                "rstrip": False,
                "normalized": False,
                "special": True,
            }
            for i, tok in enumerate(_TOKENIZER_SPECIALS)
        ],
        "normalizer": {
            "type": "Sequence",
            "normalizers": [
                {"type": "Prepend", "prepend": "\u2581"},
                {"type": "Replace", "pattern": {"String": " "}, "content": "\u2581"},
            ],
        },
        "pre_tokenizer": None,
        "post_processor": {
            "type": "TemplateProcessing",
            "single": [
                {"SpecialToken": {"id": bos, "type_id": 0}},
                {"Sequence": {"id": "A", "type_id": 0}},
            ],
            "pair": [
                {"SpecialToken": {"id": bos, "type_id": 0}},
                {"Sequence": {"id": "A", "type_id": 0}},
                {"SpecialToken": {"id": bos, "type_id": 1}},
                {"Sequence": {"id": "B", "type_id": 1}},
            ],
            "special_tokens": {bos: {"id": bos, "ids": [1], "tokens": [bos]}},
        },
        "decoder": {
            "type": "Sequence",
            "decoders": [
                {"type": "Replace", "pattern": {"String": "\u2581"}, "content": " "},
                {"type": "ByteFallback"},
                {"type": "Fuse"},
                {"type": "Strip", "content": " ", "start": 1, "stop": 0},
            ],
        },
        "model": {
            "type": "BPE",
            "dropout": None,
            "unk_token": unk,
            "continuing_subword_prefix": None,
            "end_of_word_suffix": None,
            "fuse_unk": True,
            "byte_fallback": True,
            "vocab": {piece: i for i, piece in enumerate(pieces)},
            "merges": [],
        },
    }
    tokenizer_config = {
        "tokenizer_class": "LlamaTokenizer",
        "bos_token": bos,
        "eos_token": eos,
        "unk_token": unk,
        "pad_token": None,
        "add_bos_token": True,
        "add_eos_token": False,
        "clean_up_tokenization_spaces": False,
        "legacy": False,
        "model_max_length": cfg["max_position_embeddings"],
    }
    special_tokens_map = {"bos_token": bos, "eos_token": eos, "unk_token": unk}
    return {
        "tokenizer.json": json.dumps(tokenizer, ensure_ascii=False).encode("utf-8"),
        "tokenizer_config.json": json.dumps(tokenizer_config).encode("utf-8"),
        "special_tokens_map.json": json.dumps(special_tokens_map).encode("utf-8"),
    }


def _build_llama_safetensors(cfg: dict) -> bytes:
    hidden = cfg["hidden_size"]
    heads = cfg["num_attention_heads"]
    kv_heads = cfg["num_key_value_heads"]
    head_dim = hidden // heads
    inter = cfg["intermediate_size"]
    vocab = cfg["vocab_size"]

    rng = random.Random(0)

    def rand_bytes(*shape: int) -> tuple[list[int], bytes]:
        n = 1
        for d in shape:
            n *= d
        return list(shape), array.array("f", (rng.uniform(-0.02, 0.02) for _ in range(n))).tobytes()

    tensors: dict[str, tuple[list[int], bytes]] = {
        "model.embed_tokens.weight": rand_bytes(vocab, hidden),
        "lm_head.weight": rand_bytes(vocab, hidden),
        "model.norm.weight": rand_bytes(hidden),
    }
    for i in range(cfg["num_hidden_layers"]):
        p = f"model.layers.{i}."
        tensors[p + "self_attn.q_proj.weight"] = rand_bytes(heads * head_dim, hidden)
        tensors[p + "self_attn.k_proj.weight"] = rand_bytes(kv_heads * head_dim, hidden)
        tensors[p + "self_attn.v_proj.weight"] = rand_bytes(kv_heads * head_dim, hidden)
        tensors[p + "self_attn.o_proj.weight"] = rand_bytes(hidden, heads * head_dim)
        tensors[p + "mlp.gate_proj.weight"] = rand_bytes(inter, hidden)
        tensors[p + "mlp.up_proj.weight"] = rand_bytes(inter, hidden)
        tensors[p + "mlp.down_proj.weight"] = rand_bytes(hidden, inter)
        tensors[p + "input_layernorm.weight"] = rand_bytes(hidden)
        tensors[p + "post_attention_layernorm.weight"] = rand_bytes(hidden)

    header: dict[str, Any] = {}
    buffers: list[bytes] = []
    offset = 0
    for name, (shape, data) in tensors.items():
        header[name] = {"dtype": "F32", "shape": shape, "data_offsets": [offset, offset + len(data)]}
        buffers.append(data)
        offset += len(data)

    header_bytes = json.dumps(header).encode("utf-8")
    header_bytes += b" " * ((-len(header_bytes)) % 8)
    return struct.pack("<Q", len(header_bytes)) + header_bytes + b"".join(buffers)


def _create_bedrock_import_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bedrock-import-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-read", PolicyDocument=json.dumps(policy)
    )

    def _cleanup_role() -> None:
        iam.delete_role_policy(RoleName=role_name, PolicyName="s3-read")
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    return role_arn


def _safe_delete_imported_model(bedrock, model_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        bedrock.delete_imported_model(modelIdentifier=model_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _retry_transient(fn: Callable[[], Any], *, timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AccessDeniedException", "ValidationException"):
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None, "retry loop exited without ever calling fn()"
    raise last_exc


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float, ctx=None) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(min(interval_s, max(0.0, deadline - time.monotonic())))
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
