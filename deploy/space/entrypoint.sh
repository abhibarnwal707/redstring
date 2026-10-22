#!/usr/bin/env bash
# Space start: fetch the subset graph, load it into a local Neo4j, start Neo4j, then the app.
set -euo pipefail
: "${NEO4J_PASSWORD:?set NEO4J_PASSWORD as a Space secret}"
: "${HF_TOKEN:?set HF_TOKEN as a Space secret (the graph dump repo is private)}"
GRAPH_REPO="${GRAPH_REPO:-abhibarnwal707/redstring-cti-graph-subset}"
export NEO4J_USER=neo4j NEO4J_HOME=/opt/neo4j

cd /app
echo "downloading the graph dump from ${GRAPH_REPO}"
uv run --no-sync python - <<PY
import os
from huggingface_hub import hf_hub_download
path = hf_hub_download(os.environ["GRAPH_REPO"] if "GRAPH_REPO" in os.environ else "${GRAPH_REPO}", "neo4j.dump", repo_type="dataset", token=os.environ["HF_TOKEN"], local_dir="/tmp/dump")
print("downloaded", path)
PY

mkdir -p /data/neo4j
cat > "$NEO4J_HOME/conf/neo4j.conf" <<CONF
server.directories.data=/data/neo4j
server.bolt.listen_address=127.0.0.1:7687
server.http.enabled=false
server.memory.heap.initial_size=1G
server.memory.heap.max_size=2G
server.memory.pagecache.size=1G
db.transaction.timeout=30s
CONF
neo4j-admin database load neo4j --from-path=/tmp/dump --overwrite-destination=true
neo4j-admin dbms set-initial-password "$NEO4J_PASSWORD"
rm -rf /tmp/dump
neo4j start
for i in $(seq 1 90); do
  (echo > /dev/tcp/127.0.0.1/7687) >/dev/null 2>&1 && break
  sleep 2
done
if [ "${REDSTRING_EXTRACTOR:-llama}" = "llama" ]; then
  MODEL_REPO="${MODEL_REPO:-abhibarnwal707/redstring-cti-extractor-qwen3-1.7b-v2-GGUF}"
  MODEL_FILE="${MODEL_FILE:-redstring-extractor-q8_0.gguf}"
  echo "downloading ${MODEL_FILE} from ${MODEL_REPO}"
  GGUF=$(uv run --no-sync python -c "import os; from huggingface_hub import hf_hub_download; print(hf_hub_download('${MODEL_REPO}', '${MODEL_FILE}', token=os.environ['HF_TOKEN'], local_dir='/home/user/model'))")
  export REDSTRING_EXTRACTOR="llama:${GGUF}"
fi
echo "neo4j is up; starting the app"
exec uv run --no-sync python -m redstring_cti.app
