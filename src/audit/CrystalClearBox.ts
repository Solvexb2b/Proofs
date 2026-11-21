import { ProofBundleEntity, computeSha256 } from '../database/DatabaseSchema';
import { DurableStore } from '../database/DurableStore';
import { ProofEngine } from '../proofs/ProofEngine';

export interface CustomerAuditableEvidence {
  proof_id: string;
  subject_id: string;
  claim: string;
  claim_hash: string;
  verification_verdict: 'VERIFIED' | 'FAIL' | 'PARTIAL';
  tests_passed: number;
  total_tests: number;
  formal_proofs_checked: number;
  oracles_attested: number;
  replays_matched: number;
  implementation_hash: string;
  environment_hash: string;
  reproducibility_instructions: string;
  public_audit_token: string;
  proprietary_weights_redacted: boolean;
  internal_reasoning_redacted: boolean;
}

export class CrystalClearBox {
  public static generateCustomerAuditView(bundleOrSubject: ProofBundleEntity | string): CustomerAuditableEvidence {
    return CrystalClearBox.projectCustomerEvidence(bundleOrSubject);
  }

  public static projectCustomerEvidence(bundleOrSubject: ProofBundleEntity | string): CustomerAuditableEvidence {
    let bundle: ProofBundleEntity;
    if (typeof bundleOrSubject === 'string') {
      const allBundles = Object.values(DurableStore.getInstance().getState().proof_bundles);
      const found = allBundles.find(b => b.proof_id === bundleOrSubject || b.subject_id === bundleOrSubject);
      if (!found) throw new Error(`No persisted source-bound proof bundle exists for ${bundleOrSubject}.`);
      bundle = found;
    } else {
      bundle = bundleOrSubject;
    }

    const integrity = ProofEngine.getInstance().verifyBundleIntegrity(bundle);
    if (!integrity.verified) {
      throw new Error(`Customer proof projection rejected: ${integrity.reasons.join('; ')}`);
    }
    if (bundle.claim_hash !== computeSha256(bundle.claim)) {
      throw new Error('Customer proof projection rejected: claim hash mismatch.');
    }

    const passedTests = bundle.tests.filter(t => t.passed).length;
    const checkedProofs = bundle.formal_proofs.filter(p => p.checked).length;
    const verifiedOracles = bundle.independent_oracles.filter(o => o.verified).length;
    const matchedReplays = bundle.replay_results.filter(r => r.status === 'MATCH').length;
    const payload = {
      proof_id: bundle.proof_id,
      subject_id: bundle.subject_id,
      claim_hash: bundle.claim_hash,
      implementation_hash: bundle.implementation_hash,
      tests_passed: passedTests,
      total_tests: bundle.tests.length,
      verdict: bundle.verification_status
    };

    return {
      proof_id: bundle.proof_id,
      subject_id: bundle.subject_id,
      claim: bundle.claim,
      claim_hash: bundle.claim_hash,
      verification_verdict: bundle.verification_status as 'VERIFIED' | 'FAIL' | 'PARTIAL',
      tests_passed: passedTests,
      total_tests: bundle.tests.length,
      formal_proofs_checked: checkedProofs,
      oracles_attested: verifiedOracles,
      replays_matched: matchedReplays,
      implementation_hash: bundle.implementation_hash,
      environment_hash: bundle.environment_hash,
      // Never expose unreviewed free-form evidence or private instructions.
      reproducibility_instructions: 'Request the source-bound proof manifest from the authorized verifier.',
      // Public content digest only; not a digital signature or proof of authorship.
      public_audit_token: computeSha256(JSON.stringify(payload)),
      proprietary_weights_redacted: true,
      internal_reasoning_redacted: true
    };
  }
}
