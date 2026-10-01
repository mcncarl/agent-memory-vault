#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Explanation:
    title: str
    summary: str
    recovery: tuple[str, ...]
    forbidden: tuple[str, ...] = ()


EXPLANATIONS: dict[str, Explanation] = {
    "UNCLAIMED_EXTERNAL_CHANGE": Explanation(
        title="Formal memory changed outside the current Write Gateway proposal",
        summary=(
            "Preserve the current Markdown bytes. Re-read the target and prepare a new proposal, "
            "or use an exact external-adoption proposal when the user has authorized those bytes."
        ),
        recovery=(
            "Run write read-target for the current target and scope.",
            "Prepare the complete final Markdown against the returned read token.",
            "If the current dirty bytes are intentional, Codex or Claude may prepare exact ADOPT with user-bound confirmation.",
            "Apply only the returned ADD or UPDATE proposal with its unchanged hashes and fencing token.",
        ),
        forbidden=(
            "Do not edit the formal Markdown again before re-reading it.",
            "Do not create a low-level claim or intent to bypass the Write Gateway.",
            "Do not overwrite another session's or an external editor's bytes.",
        ),
    ),
    "STALE_READ_TOKEN": Explanation(
        title="The target changed after it was read",
        summary="The proposal is based on stale bytes and cannot be applied safely.",
        recovery=(
            "Re-run write read-target.",
            "Merge the intended change into the new complete bytes.",
            "Prepare and apply a new proposal; never reuse the old proposal or fence.",
        ),
    ),
    "TARGET_CHANGED_AFTER_CLAIM": Explanation(
        title="The target changed after the proposal acquired its lease",
        summary="The previous proposal must be abandoned because its compare-and-swap base no longer matches.",
        recovery=(
            "Cancel the old proposal when it is still live.",
            "Re-read the current target and prepare a new complete proposal.",
            "Use exact ADOPT only when the current external bytes are intentional and user-authorized.",
        ),
        forbidden=("Do not revive an old fencing token or edit the state database manually.",),
    ),
    "LEASE_EXPIRED": Explanation(
        title="The proposal lease expired",
        summary="Expired write authority is terminal and cannot be renewed in place.",
        recovery=(
            "Re-read the target.",
            "Prepare a new proposal and use its new monotonic fencing token.",
        ),
    ),
    "INTENT_EXPIRED": Explanation(
        title="The Write Gateway proposal lease expired",
        summary=(
            "An ordinary expired proposal cannot be renewed. One narrow exception is an exact "
            "validated ADD or UPDATE that the original Codex or Claude session already wrote and "
            "Git committed before closeout finished."
        ),
        recovery=(
            "If this is that committed-closeout crash window, retry the unchanged original write apply request from the original task; the Gateway will verify the session, approval, fence, claim, hashes, Git history, index, and worktree before opening one bounded recovery window.",
            "Otherwise run write read-target and prepare a new proposal with a new fencing token after the old transaction has been terminally reconciled by the supported maintenance workflow.",
        ),
        forbidden=(
            "Do not edit the state database, create a low-level claim, change the proposal, or impersonate the original session.",
            "Do not treat a clean target or matching text alone as proof that recovery is allowed.",
        ),
    ),
    "APPLY_RECOVERY_REQUIRED": Explanation(
        title="The exact Write Gateway apply must finish its retained transaction",
        summary="The target reached an apply crash boundary and cannot be cancelled or replaced safely.",
        recovery=(
            "Preserve the current target and Git history.",
            "Retry the unchanged write apply request from the same actor and task so the Gateway can verify and finish the retained transaction.",
            "If exact recovery is rejected, preserve the evidence and use the reviewed maintenance workflow before preparing another proposal.",
        ),
        forbidden=(
            "Do not edit the target, reuse the fencing token for another proposal, or invoke a low-level intent or claim command.",
        ),
    ),
    "RUNTIME_TRANSITION_INCOMPLETE": Explanation(
        title="The managed Runtime is not ready",
        summary="Normal commands remain fail-closed until the installer or migrator verifies the Runtime.",
        recovery=(
            "Run memoryctl version --json and the read-only POSIX/Windows installer plan.",
            "Back up config and state to new private paths.",
            "Apply and verify the managed migration; do not execute a low-level Python script directly.",
        ),
    ),
    "INSTALL_ALREADY_RUNNING": Explanation(
        title="Another POSIX installation owns the total-install lock",
        summary="Only one installer may mutate Runtime, state, Host automation, and scheduler state at a time.",
        recovery=(
            "Let the active installation finish and read its result.",
            "Then rerun the read-only plan before starting another apply.",
        ),
        forbidden=("Do not remove the lock file or start a second installer against the same config root.",),
    ),
    "INSTALL_TRANSACTION_INPUT_MISMATCH": Explanation(
        title="A pending installation is bound to different inputs",
        summary="The retained transaction can resume only with the exact roots, backup paths, Host policy, identities, and Runtime source bundle it started with.",
        recovery=(
            "Preserve the fixed install-orchestration journal and every referenced backup.",
            "Restore the exact prior invocation and source bundle, then rerun apply to recover.",
        ),
        forbidden=("Do not reuse new backup paths, edit the journal, or overwrite the partial installation.",),
    ),
    "INSTALL_RECOVERY_REQUIRED": Explanation(
        title="The POSIX installation requires evidence-led recovery",
        summary="A prior partial install could not be compensated or its source changed after mutation, so automatic publication remains closed.",
        recovery=(
            "Preserve the transaction journal and all config, Runtime, Hook, and LaunchAgent backups it names.",
            "Run the read-only installer plan and memoryctl doctor --json for the exact retained evidence.",
            "Resume only through the reviewed recovery path for that transaction.",
        ),
        forbidden=("Do not delete the journal, overwrite backups, or downgrade this result to a warning.",),
    ),
    "INSTALL_INPUT_CHANGED_DURING_APPLY": Explanation(
        title="Installer inputs changed after mutation began",
        summary="The terminal source/input fingerprint differs from the transaction's prepared fingerprint.",
        recovery=(
            "Preserve the install-orchestration journal and referenced backups.",
            "Restore the exact prepared source and arguments, then use the transaction recovery path.",
        ),
        forbidden=("Do not continue publication with a mixed Runtime source bundle.",),
    ),
    "INSTALL_RUNTIME_SOURCE_MISMATCH": Explanation(
        title="Installed Runtime does not match the outer source binding",
        summary="The Runtime install completed with a different bundle hash from the total-install transaction's prepared source.",
        recovery=(
            "Preserve both the outer install journal and Runtime transaction journal.",
            "Restore the exact prepared checkout and recover through the same bound transaction.",
        ),
        forbidden=("Do not publish ready or replace the retained backup evidence.",),
    ),
    "INSTALL_ACTIVE_BINDING_INVALID": Explanation(
        title="The installer-to-Doctor transaction binding is malformed",
        summary="Doctor received only part of the active transaction identity or values with an invalid shape.",
        recovery=(
            "Stop the current publication attempt and preserve the outer install journal.",
            "Restart only through install-posix with the same reviewed arguments so it can issue both bound values internally.",
        ),
        forbidden=("Do not set AGENT_MEMORY_INSTALL_* variables manually to bypass the outer journal.",),
    ),
    "INSTALL_ACTIVE_BINDING_NOT_FOUND": Explanation(
        title="The active installation has no matching outer journal",
        summary="An install-scoped Doctor cannot validate an active transaction when the fixed outer journal is missing.",
        recovery=(
            "Preserve the Runtime and all backup evidence.",
            "Run the read-only installer plan and inspect the configured state/install-orchestration.jsonl path.",
        ),
        forbidden=("Do not manufacture a replacement journal or publish the Runtime ready.",),
    ),
    "INSTALL_ACTIVE_BINDING_MISMATCH": Explanation(
        title="Doctor is not observing the active outer installation transaction",
        summary="The journal is empty, terminal, or bound to a different transaction/input than the installer supplied.",
        recovery=(
            "Stop publication and preserve the journal plus Runtime and LaunchAgent child evidence.",
            "Resume only the exact transaction through install-posix after reconciling the configured Runtime root.",
        ),
        forbidden=("Do not reuse a terminal transaction identity or point Doctor at another Runtime.",),
    ),
    "BACKUP_PARENT_NOT_PRIVATE": Explanation(
        title="A backup parent directory is not private",
        summary="External backup parents must already be owner-only; managed Runtime backup parents are created as 0700.",
        recovery=(
            "Choose a new unused backup batch under the managed Runtime backups directory.",
            "Alternatively create a dedicated external parent with mode 0700, then rerun the read-only install plan.",
        ),
        forbidden=("Do not reuse a shared directory or an existing backup target.",),
    ),
    "BACKUP_TARGETS_OVERLAP": Explanation(
        title="Two installation backup targets overlap",
        summary="A file or directory backup target contains another target, so exclusive recovery evidence cannot be separated.",
        recovery=(
            "Choose one new sibling path per config, state, audit, Hook, and LaunchAgent backup.",
            "Rerun the read-only plan before apply.",
        ),
        forbidden=("Do not nest one backup target inside another or reuse a target from an earlier install.",),
    ),
    "BACKUP_TARGET_UNSAFE": Explanation(
        title="A resumed backup target changed type, mode, or identity",
        summary="A retained target is not the private regular file or directory required by its owning install stage.",
        recovery=(
            "Preserve the target and transaction journal for inspection.",
            "Resume only after the exact recovery evidence has been reviewed; otherwise use a new install transaction and new paths.",
        ),
        forbidden=("Do not overwrite, delete, or replace the retained target to force a resume.",),
    ),
    "BACKUP_TARGET_EXISTS": Explanation(
        title="A requested installation backup target already exists",
        summary="Every install requires exclusive new backup targets; an unrelated existing path cannot be reused.",
        recovery=(
            "Keep the existing path unchanged.",
            "Choose a new timestamped private backup batch and rerun the read-only plan.",
        ),
        forbidden=("Do not overwrite or delete the existing backup target.",),
    ),
    "INSTALL_BACKUP_STAGE_UNPROVEN": Explanation(
        title="A child may have written a backup without a durable outer receipt",
        summary="The interrupted stage cannot be replayed or skipped safely with the existing target.",
        recovery=(
            "Preserve the existing backup target and install-orchestration journal.",
            "Run the read-only installer plan and Doctor against the retained Runtime evidence.",
            "Start the reviewed supersede flow with an entirely new unused private backup batch.",
        ),
        forbidden=("Do not overwrite, delete, or rename the unproven target to force an in-place resume.",),
    ),
    "INSTALL_BACKUP_RECEIPT_INVALID": Explanation(
        title="The retained backup receipt is incomplete or unsafe",
        summary="The outer install journal cannot bind the completed stage to the requested private backup target.",
        recovery=(
            "Preserve the journal and every referenced backup file.",
            "Inspect the exact path, file type, owner-only mode, size, and receipt fields.",
            "Resume only when the original evidence verifies; otherwise use a reviewed supersede with new paths.",
        ),
        forbidden=("Do not edit the receipt or replace a backup to manufacture a match.",),
    ),
    "INSTALL_BACKUP_RECEIPT_MISMATCH": Explanation(
        title="A completed-stage backup no longer matches its durable receipt",
        summary="The retained file hash, size, mode, or path changed after the stage completed.",
        recovery=(
            "Stop publication and preserve the mismatched file plus install journal.",
            "Compare the retained receipt with independent backup evidence before any recovery decision.",
        ),
        forbidden=("Do not continue the install, overwrite the backup, or downgrade this mismatch to a warning.",),
    ),
    "BACKUP_PARENT_SYMLINK": Explanation(
        title="A backup parent has a symbolic-link ancestor",
        summary="The installer cannot prove that all backup writes stay inside the reviewed directory chain.",
        recovery=(
            "Choose a canonical path whose existing ancestors are real directories.",
            "Use a new owner-only backup batch and rerun the read-only installer plan.",
        ),
    ),
    "BACKUP_TARGET_OUTSIDE_MANAGED_BACKUPS": Explanation(
        title="A Runtime-local backup target is outside the managed backup namespace",
        summary="Anything below the Runtime root must be placed below its dedicated backups directory.",
        recovery=(
            "Choose a new target below <config-root>/backups.",
            "Keep config, state, scripts, locks, and active Runtime files outside the backup batch.",
        ),
    ),
    "BACKUP_TARGET_ACTIVE_PATH_OVERLAP": Explanation(
        title="A backup target overlaps an active Runtime, Vault, Git, or Host path",
        summary="The requested location could mix recovery evidence with live files.",
        recovery=(
            "Choose a separate timestamped owner-only backup batch.",
            "Rerun the read-only plan and confirm no target contains or is contained by an active path.",
        ),
    ),
    "PROJECT_CONTEXT_UNKNOWN": Explanation(
        title="The result belongs to a scoped project but the current project is unknown",
        summary="The memory is discoverable only as an analogy and cannot authorize an action.",
        recovery=(
            "Supply the current project and retrieve again.",
            "Use explicit cross-project mode only for reference-only comparison.",
        ),
    ),
    "ADOPTED_MEMORY_REQUIRES_LIVE_VERIFICATION": Explanation(
        title="An adopted memory requires current verification",
        summary="The adopted content is expired, overdue, conflicting, or otherwise non-authoritative.",
        recovery=(
            "Verify the same content version against a current source of truth.",
            "Record live_verified=yes with a bounded evidence reference, or reject the candidate.",
        ),
    ),
    "GENERATED_FILE_READ_ONLY": Explanation(
        title="This file is generated by the Runtime",
        summary="The generated navigation file must be rebuilt from canonical Markdown rather than edited by hand.",
        recovery=(
            "Change the source Markdown through the Write Gateway.",
            "Let closeout regenerate the navigation file, or run the maintenance-only index regeneration command.",
        ),
    ),
    "GOVERNANCE_MIGRATION_TARGET_INVALID": Explanation(
        title="The selected path is outside the automatic governance body",
        summary=(
            "Deterministic governance migration cannot modify archive, template, or root governance files."
        ),
        recovery=(
            "Run Doctor or content-migrate plan again and select only an automatable governed body record.",
            "For an eligible current body, run write read-target, then write prepare and apply the exact reviewed proposal.",
            "Use the ordinary Write Gateway content-update route for a separately reviewed root governance change.",
        ),
        forbidden=(
            "Do not move, relabel, or directly edit archive or template material to bypass this boundary.",
            "Do not create a low-level claim or execute the writer Python module directly.",
        ),
    ),
    "PATH_POLICY_DOWNGRADE_FORBIDDEN": Explanation(
        title="The proposed metadata weakens policy required by the canonical target path",
        summary=(
            "A document cannot use self-declared type, track, risk, or temporal metadata to lower the "
            "minimum policy derived from its canonical Vault path and content signals."
        ),
        recovery=(
            "Run write read-target for the same canonical target and scope.",
            "Prepare the complete final Markdown with the path-required memory_type and track, an explicit risk_class, and any atomic fact or evidence fields required by its content.",
            "Apply only the new proposal returned by write prepare, with its unchanged intent-bound target, metadata, hashes, and fencing token.",
        ),
        forbidden=(
            "Do not relabel a project, workflow, or decision as governance, misc, or structural to bypass its policy floor.",
            "Do not edit a prepared proposal or its intent-bound metadata before apply.",
            "Do not use a low-level claim or direct Markdown edit to bypass the Write Gateway.",
        ),
    ),
    "METADATA_RISK_CLASS_NOT_EXPLICIT": Explanation(
        title="The memory has no explicit risk class",
        summary="Risk-sensitive retrieval and write policy cannot rely on an inferred default indefinitely.",
        recovery=(
            "Re-read the target through the Write Gateway.",
            "Set the explicit risk_class required by its canonical path and content, then prepare the complete Markdown again.",
        ),
    ),
    "RISK_AUTOMATION_CLASSIFICATION_UNSAFE": Explanation(
        title="Risk automation cannot classify this memory safely",
        summary=(
            "A missing risk_class cannot be treated as ordinary from its path, "
            "document type, or other weak metadata. Human review is required "
            "before a governed migration can continue."
        ),
        recovery=(
            "Re-read the current Markdown and review whether the fact could authorize or materially influence an action.",
            "Choose an explicit risk_class from current evidence; preserve action_sensitive when uncertainty remains action-relevant.",
            "Run write read-target, then write prepare with the complete reviewed Markdown and apply only that exact confirmed proposal.",
        ),
        forbidden=(
            "Do not infer ordinary merely from a directory, memory_type, missing atomic fields, or another weak metadata signal.",
            "Do not let an automated migration self-confirm the risk decision or edit formal Markdown directly.",
            "Do not use a low-level claim or intent as a substitute for write prepare/apply.",
        ),
    ),
    "METADATA_RISK_CLASS_INVALID": Explanation(
        title="The declared memory risk class is invalid",
        summary="The metadata value is outside the Runtime's controlled risk taxonomy.",
        recovery=(
            "Re-read the target and choose a supported risk_class from the current template.",
            "Prepare and apply the corrected complete Markdown through Write Gateway v2.",
        ),
    ),
    "METADATA_RISK_CLASS_DOWNGRADE": Explanation(
        title="The declared risk class is below the canonical path floor",
        summary="Metadata cannot weaken the minimum safeguards required by the target path or content signals.",
        recovery=(
            "Use the path-required or stronger risk_class.",
            "Re-prepare the full proposal so its intent-bound metadata and content agree.",
        ),
        forbidden=("Do not relabel or move content merely to bypass the risk floor.",),
    ),
    "TEMPORAL_POLICY_REQUIRED": Explanation(
        title="Active memory has no explicit temporal policy",
        summary="An active memory cannot rely on an index-inferred lifetime or review rule.",
        recovery=(
            "Re-read the target through write read-target.",
            "Choose the explicit structural, snapshot, stable, reviewable, or expiring temporal_policy that matches the content.",
            "Add a bounded review_after_days value when the document is not an exempt routing/template/governance record, then prepare again.",
        ),
    ),
    "REVIEW_POLICY_REQUIRED": Explanation(
        title="Active memory has no bounded review schedule",
        summary="A reusable active memory needs an explicit positive review_after_days value from 1 through 3650.",
        recovery=(
            "Re-read the target and select a review interval based on how quickly the content can drift.",
            "Prepare the complete Markdown again with temporal_policy and review_after_days; do not invent a verified_at date.",
        ),
    ),
    "ACTION_SENSITIVE_FACT_REQUIRED": Explanation(
        title="Action-sensitive content is not an auditable atomic fact",
        summary="A project, workflow, or decision fact that may authorize action must be one fact per file with exact temporal evidence.",
        recovery=(
            "Split the proposed content so the file contains one atomic fact.",
            "Provide stable fact_key, exact valid_from, non-future verified_at, and a bounded evidence_ref.",
            "For expiring facts, provide an evidence-backed valid_until; never invent an expiry date.",
        ),
    ),
    "GENERATED_INDEX_OTHER_SESSION_DIRTY": Explanation(
        title="Another session has an uncommitted formal memory change",
        summary="The generated INDEX cannot take a stable whole-Vault snapshot while another session owns dirty Markdown.",
        recovery=(
            "Let the other session apply/cancel and close out its Write Gateway proposal.",
            "Re-read this session's target and retry closeout after the Vault is snapshot-stable.",
        ),
        forbidden=("Do not commit the other session's file or edit INDEX.md manually.",),
    ),
    "GENERATED_INDEX_MIGRATION_DIRTY_MEMORY": Explanation(
        title="Initial generated INDEX migration found uncommitted Vault Markdown",
        summary="The installer stopped before mutation so it cannot absorb another session's or an editor's memory bytes.",
        recovery=(
            "Finish or cancel the owning Write Gateway transaction and close it out.",
            "If the bytes are intentional external edits, re-read and adopt them through the current exact ADOPT route.",
            "Re-run the read-only installer plan after every Vault Markdown path is clean.",
        ),
        forbidden=("Do not stage, commit, overwrite, or reset the reported Markdown as an installer workaround.",),
    ),
    "GENERATED_INDEX_MIGRATION_HEAD_MISMATCH": Explanation(
        title="Initial generated INDEX migration is not bound to the current Git baseline",
        summary="The clean worktree projection or current INDEX cannot be proven to equal HEAD, so an automatic migration is unsafe.",
        recovery=(
            "Preserve the Vault and inspect the current HEAD, INDEX blob, and reported projection evidence.",
            "Resolve the baseline through the normal reviewed Git and Write Gateway workflow.",
            "Re-run the read-only installer plan before applying again.",
        ),
        forbidden=("Do not edit INDEX.md directly or use a destructive reset to manufacture a clean baseline.",),
    ),
    "GENERATED_INDEX_GIT_OPERATION_IN_PROGRESS": Explanation(
        title="Git is already performing a repository operation",
        summary="Generated INDEX publication cannot move HEAD during a merge, rebase, cherry-pick, revert, sequencer, bisect, or unresolved index state.",
        recovery=(
            "Preserve the repository and finish or abort the existing Git operation under user control.",
            "Confirm that Git reports no unmerged entries or operation sentinel, then rerun the installer plan.",
        ),
        forbidden=("Do not remove Git operation files or force-update HEAD from the installer.",),
    ),
    "GENERATED_INDEX_GIT_STATE_UNAVAILABLE": Explanation(
        title="Git operation state could not be verified",
        summary="The Runtime cannot prove that the repository has no unmerged entries or active Git operation, so generated publication is closed.",
        recovery=(
            "Preserve the worktree and run Git status under the configured Git root.",
            "Resolve repository access or corruption, then rerun the read-only installer plan.",
        ),
        forbidden=("Do not force-update HEAD or bypass the generated-index Git fence.",),
    ),
    "GENERATED_INDEX_RECOVERY_UNAVAILABLE": Explanation(
        title="Generated INDEX recovery evidence is unreadable",
        summary="The state database or retained transaction ledger cannot be read safely enough to decide whether recovery is pending.",
        recovery=(
            "Preserve the Vault, state database, and generated-index backup evidence.",
            "Run memoryctl doctor --json and repair the reported path or schema through the backed-up migration flow.",
            "Rerun the read-only installer plan before applying again.",
        ),
        forbidden=("Do not delete transaction rows, evidence directories, or INDEX.md to clear the blocker.",),
    ),
    "GENERATED_INDEX_BASE_UNSAFE": Explanation(
        title="The generated INDEX base cannot be restored safely",
        summary="Closeout stopped before publication because the existing INDEX bytes or path failed the recovery precondition.",
        recovery=(
            "Preserve all current files and inspect the reported INDEX path and hashes.",
            "Resolve the unsafe path through a reviewed maintenance recovery, then rerun closeout.",
        ),
    ),
    "GENERATED_INDEX_ROLLBACK_FAILED": Explanation(
        title="Generated INDEX recovery needs manual inspection",
        summary="A post-generation failure occurred and the Runtime could not prove that the prior INDEX bytes were restored.",
        recovery=(
            "Stop further closeouts and preserve the Vault plus transaction evidence.",
            "Compare the reported before/generated/current hashes and recover with a new reviewed Write Gateway or maintenance transaction.",
        ),
        forbidden=("Do not overwrite INDEX.md or reset the Vault destructively.",),
    ),
    "GENERATED_INDEX_RECOVERY_REQUIRED": Explanation(
        title="Generated INDEX transaction requires evidence-led recovery",
        summary="A retained generated-index transaction is unresolved or failed; ordinary closeout remains fail-closed.",
        recovery=(
            "Run memoryctl doctor --json and preserve the transaction evidence directory reported by the Runtime.",
            "Retry closeout once: an exact commit or restored base plus successful rescan is resolved automatically without overwriting later bytes.",
            "If Doctor still reports a conflict, use a reviewed maintenance recovery; keep the failed row and evidence until resolution is recorded.",
        ),
        forbidden=("Do not edit INDEX.md, delete transaction evidence, or update the state database directly.",),
    ),
    "GENERATED_INDEX_COMMIT_EVIDENCE_INVALID": Explanation(
        title="Generated INDEX commit does not match its closeout transaction",
        summary="The candidate commit failed its exact parent, INDEX blob, Vault identity, or full-Vault input projection check.",
        recovery=(
            "Preserve the current worktree and inspect Doctor's generated-index transaction counts.",
            "Retry closeout only after the original base and transaction-private evidence are available.",
        ),
        forbidden=("Do not bless a later descendant commit merely because it contains the same INDEX bytes.",),
    ),
    "GENERATED_INDEX_RECOVERY_CONFLICT": Explanation(
        title="Generated INDEX recovery found later unknown bytes",
        summary="The live INDEX is neither the bound pre-closeout base nor the transaction's generated bytes.",
        recovery=(
            "Preserve the live INDEX and private transaction evidence.",
            "Review the concurrent change, then resolve it through a new closeout or explicit maintenance transaction.",
        ),
        forbidden=("Do not overwrite the live file with rollback evidence.",),
    ),
    "GENERATED_INDEX_ROLLBACK_REINDEX_FAILED": Explanation(
        title="Generated INDEX bytes were restored but the derived index rescan failed",
        summary="The failure is retained and will be retried only through objective base and rescan evidence.",
        recovery=(
            "Resolve the SQLite availability or schema error reported by Doctor.",
            "Retry closeout; a successful base hash check and rescan will transition the retained failure to rolled_back.",
        ),
    ),
    "GENERATED_INDEX_VAULT_ROOT_CHANGED": Explanation(
        title="Generated INDEX transaction belongs to a different Vault root",
        summary="Recovery refused to apply transaction evidence after the configured Vault identity changed.",
        recovery=(
            "Restore the intended Runtime/Vault configuration or inspect the transaction under its original Vault.",
            "Keep both Vaults and the transaction evidence unchanged until the binding is resolved.",
        ),
        forbidden=("Do not reuse rollback evidence across Vault roots.",),
    ),
}


_EXPIRED_COMMITTED_REJECTION = Explanation(
    title="Exact committed-write recovery was rejected",
    summary=(
        "The retained expired proposal no longer satisfies every authorization, content, claim, "
        "fence, file-safety, and Git-history invariant required for automatic completion."
    ),
    recovery=(
        "Preserve the target, Git history, and Runtime state evidence; run memoryctl doctor --json.",
        "Retry the unchanged original write apply only when the reported condition was transient and every original binding remains exact.",
        "If the bytes, history, ownership, or recovery window genuinely changed, use the reviewed maintenance workflow to terminally reconcile the old transaction before running write read-target and preparing a new proposal.",
    ),
    forbidden=(
        "Do not edit the state database, manufacture a receipt, force-renew the lease, create a low-level claim, or rewrite Git history.",
    ),
)

for _reason_code in (
    "EXPIRED_VALIDATED_RECOVERY_BINDING_CHANGED",
    "EXPIRED_VALIDATED_RECOVERY_CLAIM_CHANGED",
    "EXPIRED_VALIDATED_RECOVERY_COMMIT_CONTENT_MISMATCH",
    "EXPIRED_VALIDATED_RECOVERY_EXPIRY_INVALID",
    "EXPIRED_VALIDATED_RECOVERY_GIT_DIVERGED",
    "EXPIRED_VALIDATED_RECOVERY_STATE_CHANGED",
    "EXPIRED_VALIDATED_RECOVERY_TARGET_DRIFT",
    "EXPIRED_VALIDATED_RECOVERY_TARGET_HISTORY_CHANGED",
    "EXPIRED_VALIDATED_RECOVERY_WINDOW_ELAPSED",
    "EXPIRED_VALIDATED_RECOVERY_WORKTREE_DIRTY",
    "EXPIRED_VALIDATED_RECOVERY_WORKTREE_UNSAFE",
):
    EXPLANATIONS[_reason_code] = _EXPIRED_COMMITTED_REJECTION


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Explain a stable Agent Memory reason code.")
    parser.add_argument("reason_code")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    reason_code = str(args.reason_code).strip().upper()
    detail = EXPLANATIONS.get(reason_code)
    if detail is None:
        payload = {
            "ok": False,
            "reason_code": reason_code,
            "error": "UNKNOWN_REASON_CODE",
            "known_reason_codes": sorted(EXPLANATIONS),
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"unknown reason code: {reason_code}")
        return 2
    payload = {
        "ok": True,
        "reason_code": reason_code,
        "title": detail.title,
        "summary": detail.summary,
        "recovery": list(detail.recovery),
        "forbidden": list(detail.forbidden),
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"reason_code={reason_code}")
        print(detail.title)
        print(detail.summary)
        for index, step in enumerate(detail.recovery, 1):
            print(f"{index}. {step}")
        for warning in detail.forbidden:
            print(f"forbidden: {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
