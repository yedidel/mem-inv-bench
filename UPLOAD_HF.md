# Publishing the benchmark to the Hugging Face Hub

This folder (`release_hf/`) is the **dataset**: scenarios (JSON + JSONL) plus the result
logs, with a dataset card (`README.md`). Publish it as a Hugging Face **Dataset**.

## One time
1. Create a free account at https://huggingface.co.
2. Create a **write** access token: https://huggingface.co/settings/tokens -> "New token"
   -> role **Write** -> copy it.
3. Install the client:
   ```bash
   pip install -U "huggingface_hub[cli]"
   ```
   (Newer installs expose the command as `hf`; older ones as `huggingface-cli`. Both work.)

## Upload
```bash
# 1) log in (paste the write token when prompted)
hf auth login                 # older: huggingface-cli login

# 2) create the dataset repo (one time) -> USERNAME/MEM-INV-Bench
hf repo create MEM-INV-Bench --repo-type dataset

# 3) upload everything in this folder to the repo root
cd release_hf
hf upload USERNAME/MEM-INV-Bench . . --repo-type dataset
```
The two dots are `<local-path> <path-in-repo>`. Your dataset is then live at
`https://huggingface.co/datasets/USERNAME/MEM-INV-Bench`, and the viewer will render the
`scenarios` and `scenarios_large` configs from the JSONL files.

## After uploading
1. Put the dataset URL into the paper footnote placeholder `USERNAME` and
   into the GitHub repo's README ("Benchmark dataset (Hugging Face)" line).
2. Edit the two `USERNAME` links inside this folder's `README.md` (the GitHub link and the
   `load_dataset(...)` example) to your username.
3. To update later, re-run the `hf upload ...` command; it syncs changed files.

## Notes
- **Repo type must be `dataset`** so the card renders and the viewer loads the JSONL.
- If the viewer errors on the nested scenario schema, it is only cosmetic: the JSON/JSONL
  files still download and parse, and `load_dataset` still works. You can remove the
  `configs:` block from the card's front-matter to silence it.
- Everything here is small text/JSON (well under HF's size limits), so Git-LFS is not needed.
- Keep the dataset in sync with the GitHub repo's `data/` and `results/` after any re-run.
