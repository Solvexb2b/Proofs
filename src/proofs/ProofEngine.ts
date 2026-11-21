import { ProofBundleEntity, computeSha256 } from '../database/DatabaseSchema';
import { DurableStore } from '../database/DurableStore';

const SHA256_HEX = /^[a-f0-9]{64}$/i;

export class ProofEngine {
  private static instance: ProofEngine | null = null;
  private bundles: Map<string, ProofBundleEntity> = new Map();

  private constructor() {
    // Load only persisted records. Never manufacture a proof bundle during startup.
    const persisted = DurableStore.getInstance().getState().proof_bundles || {};
    for (const [id, bundle] of Object.entries(persisted)) this.bundles.set(id, bundle);
  }

  public static getInstance(): ProofEngine {
    if (!ProofEngine.instance) ProofEngine.instance = new ProofEngine();
    return ProofEngine.instance;
  }

  public getBundle(proofId: string): ProofBundleEntity | undefined {
    return this.bundles.get(proofId);
  }

  public getAllBundles(): ProofBundleEntity[] {
    return Array.from(this.bundles.values());
  }

  public verifyBundleIntegrity(bundle: ProofBundleEntity): { verified: boolean; reasons: string[] } {
    const reasons: string[] = [];
    if (!bundle || typeof bundle !== 'object') return { verified: false, reasons: ['Missing proof bundle'] };

    if (!bundle.proof_id || !bundle.subject_id) reasons.push('Missing proof or subject identity');
    if (!bundle.claim || bundle.claim_hash !== computeSha256(bundle.claim)) reasons.push('Claim hash mismatch');
    if (!SHA256_HEX.test(bundle.implementation_hash || '') ||
        !SHA256_HEX.test(bundle.environment_hash || '') ||
        !SHA256_HEX.test(bundle.dependency_hash || '')) reasons.push('Implementation, environment, or dependency digest invalid');
    if (!Number.isFinite(bundle.timestamp) || bundle.timestamp <= 0) reasons.push('Invalid proof timestamp');
    if (!Array.isArray(bundle.source_references) || bundle.source_references.length === 0 ||
        bundle.source_references.some(ref => typeof ref !== 'string' || !ref.trim())) reasons.push('Missing source-bound references');

    if (!Array.isArray(bundle.tests) || bundle.tests.length === 0) {
      reasons.push('Missing empirical test receipts');
    } else {
      for (const test of bundle.tests) {
        if (!test.passed) reasons.push('One or more empirical tests failed');
        const expected = computeSha256(test.test_id + ':' + test.passed + ':' + test.duration_ms);
        if (!SHA256_HEX.test(test.receipt_hash || '') || test.receipt_hash !== expected) reasons.push('Empirical test receipt hash invalid');
      }
    }

    if (!Array.isArray(bundle.formal_proofs) || bundle.formal_proofs.length === 0) {
      reasons.push('Missing formal proof records');
    } else {
      for (const proof of bundle.formal_proofs) {
        const expected = computeSha256(proof.system + ':' + proof.specification + ':' + proof.checked + ':' + proof.classification + ':' + (proof.solver_result || ''));
        if (!SHA256_HEX.test(proof.proof_term_hash || '') || proof.proof_term_hash !== expected) reasons.push('Formal proof term hash invalid');
        if (!proof.checked && proof.classification !== 'CLAIM_ONLY') reasons.push('Unverified formal proof record');
      }
      if (!bundle.formal_proofs.some(proof => proof.checked &&
        (proof.classification === 'MACHINE_CHECKED_FORMAL_PROOF' || proof.classification === 'MACHINE_CHECKED_MODEL_PROOF'))) {
        reasons.push('No machine-checked formal/model proof record');
      }
    }

    if (!Array.isArray(bundle.independent_oracles) || bundle.independent_oracles.length === 0) {
      reasons.push('Missing independent oracle attestations');
    } else {
      for (const oracle of bundle.independent_oracles) {
        const expected = computeSha256(oracle.oracle_id + ':' + oracle.name + ':' + oracle.verified);
        if (!SHA256_HEX.test(oracle.attestation_hash || '') || oracle.attestation_hash !== expected) reasons.push('Oracle attestation digest invalid');
      }
    }
    // A self-asserted boolean and an unsigned digest are not an oracle signature.
    reasons.push('Trusted-key oracle signature verification is not configured');

    if (!Array.isArray(bundle.replay_results) || bundle.replay_results.length === 0) {
      reasons.push('Missing deterministic replay records');
    } else {
      for (const replay of bundle.replay_results) {
        if (replay.status !== 'MATCH' || !SHA256_HEX.test(replay.expected_hash || '') ||
            replay.expected_hash !== replay.observed_hash) reasons.push('Replay trace missing, malformed, or divergent');
      }
    }

    if (bundle.verification_status !== 'VERIFIED') reasons.push('Bundle is not VERIFIED');
    return { verified: reasons.length === 0, reasons: Array.from(new Set(reasons)) };
  }
}
