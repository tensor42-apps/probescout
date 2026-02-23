# Backend (Python RestAPI)

All backend code resides here. Python-based. Exposes RestAPI for the agentic nmap service.

## Setup

- Create a venv and install deps: `python3 -m venv .venv && .venv/bin/python3 -m pip install -r requirements.txt`
- API key: copy `config/openai.key.ignore.example` to `config/openai.key.ignore` and put your OpenAI API key on the first line (or `KEY=your-key`).

## Run

- API server (port 12001): `./startup_backend.sh` (from this directory) or `uvicorn app:app --reload --port 12001`
- CLI (target from config): `python cli.py`

See `docs/implementation_design.md` for implementation spec. Backend is single source of truth for decisions and state.
