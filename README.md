# probescout
demo app

## Keeping secrets out of the repo

- **API keys:** Put OpenAI (or other) keys only in files that are gitignored (e.g. `app/backend/config/openai.key.ignore`). Never commit `*.key`, `*.key.ignore`, or `.env` files.
- **Git remote:** Prefer SSH or a credential helper instead of putting a token in the remote URL (`git remote set-url origin git@github.com:...` or use `git config credential.helper`).
- **Logs and results:** Logs, report.txt, llm_log.txt, nmap XML, and scan result JSON under `app/backend/logs/` are ignored; keep them out of commits.
