# Publishing the code to GitHub

This folder (`release_github/`) is the full, runnable repository: code, formal model,
scenarios, and result logs. Steps to publish it.

## One time
1. Create a free account at https://github.com and (optionally) install the `gh` CLI
   (https://cli.github.com) or just use `git`.
2. On github.com, create a new **empty** repository, e.g. `mem-inv-bench` (no README/license,
   since this folder already has them).

## Push with git
```bash
cd release_github

# (recommended) add a .gitignore for python caches
printf '__pycache__/\n*.pyc\n.DS_Store\n' > .gitignore

git init
git add .
git commit -m "MEM-INV-Bench: harness, formal model, scenarios, and result logs"
git branch -M main
git remote add origin https://github.com/USERNAME/mem-inv-bench.git   # <-- your repo URL
git push -u origin main
```
(With the `gh` CLI you can replace the create+remote steps with
`gh repo create mem-inv-bench --public --source=. --remote=origin --push`.)

## After pushing
1. Your code is live at `https://github.com/USERNAME/mem-inv-bench`.
2. Put that URL into:
   - the paper footnote placeholder `USERNAME`,
   - this repo's `README.md` (top "Code / GitHub" line),
   - the Hugging Face dataset card (the "Code / harness" link).
3. To update later, just `git add -A && git commit -m "..." && git push`.

## Notes
- `formal/tla2tools.jar` is **not** included (third-party binary). `formal/DOWNLOAD_TLA.md`
  tells users how to fetch it. This keeps the repo small and license-clean.
- Everything here is small text/JSON, so no Git-LFS is needed.
- **Anonymity:** IEEE TDSC uses single-anonymous review, so a named release under your own
  account is fine, and that is what we assume here. No anonymization is needed. (Only if you
  later submit to a double-blind venue would you anonymize, e.g. via
  https://anonymous.4open.science.)
