"""deploy-knowledge-base-cfn-behaves."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-knowledge-base-cfn-behaves"
GROUP = "state-machine"
SERVICES = ["bedrock-agent"]

EMBEDDING_MODEL = "amazon.titan-embed-text-v1"
EMBEDDING_DIMENSION = 1536

_TEMPLATE = """AWSTemplateFormatVersion: "2010-09-09"
Description: sim2real behavioral check - bedrock knowledge base + data source over S3 Vectors
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: __DATA_BUCKET_NAME__
  VectorBucket:
    Type: AWS::S3Vectors::VectorBucket
    Properties:
      VectorBucketName: __VECTOR_BUCKET_NAME__
  VectorIndex:
    Type: AWS::S3Vectors::Index
    Properties:
      VectorBucketArn: !Ref VectorBucket
      IndexName: __INDEX_NAME__
      DataType: float32
      Dimension: __DIMENSION__
      DistanceMetric: cosine
  KnowledgeBaseRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: __ROLE_NAME__
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: bedrock.amazonaws.com
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                aws:SourceAccount: !Sub "${AWS::AccountId}"
              ArnLike:
                aws:SourceArn: !Sub "arn:${AWS::Partition}:bedrock:${AWS::Region}:${AWS::AccountId}:knowledge-base/*"
      Policies:
        - PolicyName: kb-runtime-permissions
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: bedrock:InvokeModel
                Resource: !Sub "arn:${AWS::Partition}:bedrock:${AWS::Region}::foundation-model/__EMBEDDING_MODEL__"
              - Effect: Allow
                Action:
                  - s3vectors:GetIndex
                  - s3vectors:PutVectors
                  - s3vectors:GetVectors
                  - s3vectors:QueryVectors
                  - s3vectors:DeleteVectors
                  - s3vectors:ListVectors
                Resource:
                  - !Ref VectorBucket
                  - !Ref VectorIndex
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:ListBucket
                Resource:
                  - !GetAtt DataBucket.Arn
                  - !Sub "${DataBucket.Arn}/*"
  KnowledgeBaseResource:
    Type: AWS::Bedrock::KnowledgeBase
    Properties:
      Name: __KB_NAME__
      RoleArn: !GetAtt KnowledgeBaseRole.Arn
      KnowledgeBaseConfiguration:
        Type: VECTOR
        VectorKnowledgeBaseConfiguration:
          EmbeddingModelArn: !Sub "arn:${AWS::Partition}:bedrock:${AWS::Region}::foundation-model/__EMBEDDING_MODEL__"
      StorageConfiguration:
        Type: S3_VECTORS
        S3VectorsConfiguration:
          VectorBucketArn: !Ref VectorBucket
          IndexArn: !Ref VectorIndex
  DataSourceResource:
    Type: AWS::Bedrock::DataSource
    Properties:
      KnowledgeBaseId: !Ref KnowledgeBaseResource
      Name: __DS_NAME__
      DataSourceConfiguration:
        Type: S3
        S3Configuration:
          BucketArn: !GetAtt DataBucket.Arn
Outputs:
  KnowledgeBaseId:
    Value: !Ref KnowledgeBaseResource
  DataSourceId:
    Value: !GetAtt DataSourceResource.DataSourceId
  DataBucketName:
    Value: !Ref DataBucket
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed KnowledgeBase+DataSource (S3 Vectors) runs StartIngestionJob to completion."""
    cfn = ctx.client("cloudformation")
    bedrock_agent = ctx.client("bedrock-agent")
    s3 = ctx.client("s3")

    stack_name = ctx.unique_name("sim2real-bkb-cfn-")
    data_bucket_name = ctx.unique_name("sim2real-bkb-data-").lower()
    vector_bucket_name = ctx.unique_name("sim2real-bkb-vec-").lower()
    role_name = ctx.unique_name("sim2real-bkb-role-")
    kb_name = ctx.unique_name("sim2real-kb-")
    ds_name = ctx.unique_name("sim2real-ds-")
    index_name = ctx.unique_name("sim2real-idx-").lower()

    template = (
        _TEMPLATE.replace("__DATA_BUCKET_NAME__", data_bucket_name)
        .replace("__VECTOR_BUCKET_NAME__", vector_bucket_name)
        .replace("__INDEX_NAME__", index_name)
        .replace("__DIMENSION__", str(EMBEDDING_DIMENSION))
        .replace("__ROLE_NAME__", role_name)
        .replace("__EMBEDDING_MODEL__", EMBEDDING_MODEL)
        .replace("__KB_NAME__", kb_name)
        .replace("__DS_NAME__", ds_name)
    )

    cfn.create_stack(StackName=stack_name, TemplateBody=template, Capabilities=["CAPABILITY_NAMED_IAM"])
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_stack_complete(ctx, stack_name, "CREATE_COMPLETE", {"ROLLBACK_COMPLETE", "CREATE_FAILED"})

    outputs = _stack_outputs(ctx, stack_name)
    kb_id = outputs["KnowledgeBaseId"]
    ds_id = outputs["DataSourceId"]
    bucket = outputs["DataBucketName"]

    _wait_kb_status(ctx, kb_id, timeout_s=180.0)

    doc_key = "sim2real-doc.txt"
    s3.put_object(
        Bucket=bucket,
        Key=doc_key,
        Body=b"Amazon Bedrock Knowledge Bases let agents retrieve relevant context at runtime.",
    )
    ctx.on_cleanup(lambda: _delete_object_if_bucket_present(s3, bucket, doc_key))

    job = bedrock_agent.start_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds_id)["ingestionJob"]
    job_id = job["ingestionJobId"]

    final_job = _wait_ingestion_job(ctx, kb_id, ds_id, job_id, timeout_s=600.0)
    assert final_job["status"] == "COMPLETE", f"ingestion job never completed, last status={final_job['status']}"
    assert final_job["statistics"]["numberOfDocumentsScanned"] >= 1

    s3.delete_object(Bucket=bucket, Key=doc_key)
    _delete_stack(ctx, stack_name)
    not_found, message = _error(lambda: bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id))
    assert not_found == "ResourceNotFoundException", (
        f"expected the CFN-deployed knowledge base to be gone after stack teardown, got {not_found!r}"
    )
    assert message == f"KnowledgeBase with id {kb_id} is not found.", message


def _wait_stack_complete(ctx, stack_name, success_status, failure_statuses, timeout_s=900.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        last_status = stacks[0]["StackStatus"]
        if last_status == success_status:
            return
        if last_status in failure_statuses:
            raise AssertionError(f"stack {stack_name} reached {last_status}, expected {success_status}")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} never reached {success_status}, last={last_status}")


def _stack_outputs(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 900.0
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except Exception:
            return
        if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
            return
        if stacks[0]["StackStatus"] == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED while tearing down")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} never reached DELETE_COMPLETE within 900s")


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_object_if_bucket_present(s3, bucket, key):
    """The run deletes the stack (and its bucket) itself; a bucket already gone is not a teardown failure."""
    try:
        s3.delete_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _wait_kb_status(ctx, kb_id, timeout_s=180.0, interval_s=5.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"]
        if status in ("ACTIVE", "FAILED"):
            break
        time.sleep(interval_s)
    assert status == "ACTIVE", f"knowledge base never reached ACTIVE, last status={status}"


def _wait_ingestion_job(ctx, kb_id, ds_id, job_id, timeout_s=600.0, interval_s=10.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    job = None
    while time.monotonic() < deadline:
        job = bedrock_agent.get_ingestion_job(
            knowledgeBaseId=kb_id, dataSourceId=ds_id, ingestionJobId=job_id
        )["ingestionJob"]
        if job["status"] in ("COMPLETE", "FAILED"):
            return job
        time.sleep(interval_s)
    return job


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
