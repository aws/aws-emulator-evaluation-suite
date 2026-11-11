# The image asset. cdk-assets builds this at `cdk deploy` time and pushes it to the bootstrap
# environment's container-asset repository, which is the whole subject of this workflow.
#
# The base image comes from ECR Public rather than Docker Hub: the pull happens on the machine
# running the check and on the ECS task's behalf, and an anonymous Docker Hub pull is rate-limited
# per source IP — a shared build host would turn that into an intermittent deploy failure that looks
# like a target defect.
FROM public.ecr.aws/docker/library/python:3.12-alpine

WORKDIR /app
COPY server.py /app/server.py

ENV PORT=8080
EXPOSE 8080

CMD ["python3", "/app/server.py"]
