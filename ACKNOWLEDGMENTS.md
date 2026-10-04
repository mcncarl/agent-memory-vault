# Acknowledgments

This project is inspired by [EverOS](https://github.com/EverMind-AI/EverOS) by EverMind AI.

EverOS helped clarify several design directions, including Markdown as the source of truth, local indexing, user and agent memory separation, orthogonal retrieval fields, and agent self-evolution patterns.

This repository is not affiliated with EverMind AI and does not include EverOS source code.

## Contributors

Thanks to the community contributors below. Each commit listed here was completed using their pull request as its starting draft.

[@VailElla](https://github.com/VailElla) contributed [PR #2](https://github.com/mcncarl/agent-memory-vault/pull/2), which exports sourced environment variables, and [PR #3](https://github.com/mcncarl/agent-memory-vault/pull/3), which fails closed on an unhealthy pre-write search. They landed as [`663a514`](https://github.com/mcncarl/agent-memory-vault/commit/663a514) (Export bootstrap environment safely) and [`0379344`](https://github.com/mcncarl/agent-memory-vault/commit/0379344) (Fail closed on unhealthy reconcile search).

[@ChenTingToDo](https://github.com/ChenTingToDo) contributed [PR #4](https://github.com/mcncarl/agent-memory-vault/pull/4), which adds native Windows support. It landed as [`078cfa7`](https://github.com/mcncarl/agent-memory-vault/commit/078cfa7) (Harden cross-platform runtime and bootstrap).
