# One Lambda image for the PkgGuard backend. The API, scan worker and failure handler
# use it with different handler commands (set in infra/template.yaml).
FROM public.ecr.aws/lambda/python:3.12

COPY --from=ghcr.io/astral-sh/uv:0.9.10 /uv /bin/uv
ENV UV_PYTHON=/var/lang/bin/python3.12 UV_NO_CACHE=1

WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv export --frozen --no-dev --no-emit-project --no-hashes -o requirements.txt \
 && uv pip install --target "${LAMBDA_TASK_ROOT}" -r requirements.txt

COPY src ./src
RUN uv pip install --target "${LAMBDA_TASK_ROOT}" --no-deps . \
 && rm -rf /build

WORKDIR ${LAMBDA_TASK_ROOT}
CMD ["pkgguard_analyzer.cloud.scan_handler.handler"]
