#!/usr/bin/env bash
# Adapter on the Hub -> merged 16-bit model -> GGUF f16 -> Q4_K_M -> Ollama models.
# Needs: uv, Docker (for the Linux quantiser: this Mac's C toolchain cannot link), Ollama.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/Applications/Docker.app/Contents/Resources/bin:/usr/local/bin:$HOME/.local/bin:$PATH"

uv run python finetune/merge_adapter.py
[ -d data/tools/llama.cpp ] || git clone --depth 1 https://github.com/ggml-org/llama.cpp.git data/tools/llama.cpp
mkdir -p finetune/gguf
uv run --with gguf --with sentencepiece python data/tools/llama.cpp/convert_hf_to_gguf.py finetune/merged \
  --outfile finetune/gguf/redstring-extractor-f16.gguf --outtype f16
docker run --rm -v "$PWD/finetune/gguf:/m" ghcr.io/ggml-org/llama.cpp:full \
  --quantize /m/redstring-extractor-f16.gguf /m/redstring-extractor-q4_k_m.gguf Q4_K_M
(cd finetune && ollama create redstring-extractor -f Modelfile && ollama create redstring-extractor-q4 -f Modelfile.q4)
