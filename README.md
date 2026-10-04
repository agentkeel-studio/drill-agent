# An agent from the agentkeel template

This repository holds one agent. It starts as a copy of agentkeel's
reference agent, `refagent`, which answers title-availability questions
from a rights table. You make it yours, and agentkeel ships it.

Start with the quickstart:
<https://github.com/andaro74/agentkeel/blob/main/docs/developer/quickstart.md>

What is here:

| File | What it is |
|---|---|
| `manifest.yaml` | The agent's name, model, guardrail and owners (seats). Every seat starts empty. |
| `goldens/` | The agent's own tests. Starts empty. You add at least one ordinary question and one trap. |
| `data/table.json`, `data/clauses.json` | The rows and clauses the agent answers from. Each test cites one of each. |
| `agent.py`, `server.py`, `prompt.txt`, `tools/` | The agent itself. |

What you cannot change from here:

- **The platform check.** Every pull request needs a passing check named
  `platform-check`, posted by agentkeel's GitHub App. A workflow in this
  repository can post a check with that name; GitHub documents that a
  check bound to an App is accepted from that App only. It was attempted
  once, as M06's seed S2: the stand-in's check did not let the pull
  request merge. At that time the platform's own check was refusing every
  head for a fault of its own. It was to be tried again at M07 and was
  not, so that question is still open.
- **The deploy.** agentkeel deploys this agent from its own pipeline after
  a merge. Nothing in this repository holds a cloud credential.
- **The guardrail.** Every agent from the template uses the platform's,
  built from agentkeel's `agents/refagent/rules/`. A `rules/` folder here
  is not read.
