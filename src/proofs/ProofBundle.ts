import { ProofBundleEntity, FormalProofRecord, FormalProofClassification, computeSha256 } from '../database/DatabaseSchema';
import { Z3ProofResult } from './Z3FormalProofEngine';
import { NOPOTCertificate } from './NOPOTProof';

export class ProofBundleBuilder {
  private bundle: ProofBundleEntity;

  constructor(proofId: string, subjectId: string, claim: string) {
    this.bundle = {
      proof_id: proofId, subject_id: subjectId, claim, claim_hash: computeSha256(claim),
      evidence: [], tests: [], formal_proofs: [], independent_oracles: [], replay_results: [],
      implementation_hash: computeSha256('EMPTY_IMPL'),
      environment_hash: computeSha256('SOVEREIGN_NODE_SANDBOX'),
      dependency_hash: computeSha256('ZERO_SPECULATIVE_DEPS'),
      source_references: [], timestamp: Date.now(),
      verifier_identity: 'DAISY_HAMINJA_PROOF_ENGINE_V1',
      verification_status: 'PARTIAL', limitations: [],
      reproducibility_instructions: 'Run the isolated enterprise verification suite.'
    };
  }

  public setImplementation(sourceCode: string): this {
    this.bundle.implementation_hash = computeSha256(sourceCode);
    return this;
  }

  public addTest(testId: string, description: string, passed: boolean, durationMs: number): this {
    this.bundle.tests.push({
      test_id: testId, description, passed, duration_ms: durationMs,
      receipt_hash: computeSha256(testId + ':' + passed + ':' + durationMs)
    });
    return this;
  }

  public addFormalProof(
    system: 'Z3_SMT' | 'LEAN4' | 'ISABELLE' | 'NOPOT' | 'TYPE_THEORY',
    spec: string, checked: boolean,
    classification: FormalProofClassification = 'CLAIM_ONLY',
    checkerDetails?: { engine?: string; version?: string; solver_result?: string; duration_ms?: number; stdout?: string }
  ): this {
    let finalClassification = classification;
    let finalChecked = checked;
    if (classification === 'MACHINE_CHECKED_FORMAL_PROOF' || classification === 'MACHINE_CHECKED_MODEL_PROOF') {
      if (!checkerDetails?.solver_result || !checkerDetails?.engine) {
        finalClassification = 'CLAIM_ONLY';
        finalChecked = false;
      }
    }
    const record: FormalProofRecord = {
      system, specification: spec, checked: finalChecked, classification: finalClassification,
      proof_term_hash: computeSha256(system + ':' + spec + ':' + finalChecked + ':' + finalClassification + ':' + (checkerDetails?.solver_result || '')),
      checker_engine: checkerDetails?.engine, checker_version: checkerDetails?.version,
      solver_result: checkerDetails?.solver_result, execution_duration_ms: checkerDetails?.duration_ms,
      stdout_summary: checkerDetails?.stdout
    };
    this.bundle.formal_proofs.push(record);
    return this;
  }

  public addZ3Proof(proofResult: Z3ProofResult, isModelProof: boolean = false): this {
    const classification: FormalProofClassification = isModelProof ? 'MACHINE_CHECKED_MODEL_PROOF' : 'MACHINE_CHECKED_FORMAL_PROOF';
    return this.addFormalProof(
      'Z3_SMT',
      '[' + proofResult.theorem_id + '] ' + proofResult.theorem_name + ' (Z3 Engine) - Claim: ' + proofResult.claim,
      proofResult.proved && proofResult.solver_result === 'unsat',
      classification,
      {
        engine: proofResult.solver_engine, version: proofResult.solver_version,
        solver_result: proofResult.solver_result.toUpperCase(),
        duration_ms: proofResult.execution_time_ms, stdout: proofResult.explanation
      }
    );
  }

  public addNOPOTProof(cert: NOPOTCertificate, z3Result?: Z3ProofResult): this {
    if (z3Result && z3Result.proved && z3Result.solver_result === 'unsat') {
      return this.addFormalProof(
        'NOPOT',
        'NOPOT Bounded Termination (' + cert.target_algorithm + ') - Inductive Step & Well-Founded Measure: ' + cert.variant_function,
        true, 'MACHINE_CHECKED_MODEL_PROOF',
        {
          engine: z3Result.solver_engine, version: z3Result.solver_version,
          solver_result: 'UNSAT (' + z3Result.theorem_id + ')',
          duration_ms: z3Result.execution_time_ms,
          stdout: 'Termination bounded to max ' + cert.bounded_steps_upper_bound + ' steps, measured ' + cert.actual_measured_steps + ' steps'
        }
      );
    }
    return this.addFormalProof(
      'NOPOT', 'NOPOT Bounded Termination (' + cert.target_algorithm + ') - Concrete Execution Only',
      cert.termination_proved, 'EXECUTABLE_VERIFICATION',
      {
        engine: 'NOPOT Concrete Step Verifier',
        solver_result: cert.termination_proved ? 'CONVERGED_BOUNDED' : 'DIVERGED',
        duration_ms: 0,
        stdout: 'Concrete steps: ' + cert.actual_measured_steps + ' of max ' + cert.bounded_steps_upper_bound
      }
    );
  }

  public addLean4Proof(filePath: string): this {
    return this.addFormalProof(
      'LEAN4', 'Lean4 Formalization Source File: ' + filePath, false, 'CLAIM_ONLY',
      { engine: 'Lean 4 Theorem Prover', solver_result: 'UNAVAILABLE_ENVIRONMENT',
        stdout: 'Lean4 executable not detected; formal check was not executed.' }
    );
  }

  public addOracle(oracleId: string, name: string, method: string, _selfAssertedVerified: boolean): this {
    // A caller-provided boolean is not an independent attestation.
    this.bundle.independent_oracles.push({
      oracle_id: oracleId, name, method,
      attestation_hash: computeSha256(oracleId + ':' + name + ':' + method),
      verified: false
    });
    this.bundle.limitations.push('Oracle ' + oracleId + ' is recorded but not authenticated by a trusted public key.');
    return this;
  }

  public addReplay(replayId: string, expectedHash: string, observedHash: string): this {
    const match = expectedHash === observedHash;
    this.bundle.replay_results.push({
      replay_id: replayId, status: match ? 'MATCH' : 'MISMATCH',
      expected_hash: expectedHash, observed_hash: observedHash
    });
    return this;
  }

  public addEvidence(item: string): this { this.bundle.evidence.push(item); return this; }
  public addSourceReference(ref: string): this { this.bundle.source_references.push(ref); return this; }
  public addLimitation(limitation: string): this { this.bundle.limitations.push(limitation); return this; }

  public seal(): ProofBundleEntity {
    const allTestsPassed = this.bundle.tests.length > 0 && this.bundle.tests.every(t => t.passed);
    const machineChecked = this.bundle.formal_proofs.some(f => f.checked &&
      (f.classification === 'MACHINE_CHECKED_FORMAL_PROOF' || f.classification === 'MACHINE_CHECKED_MODEL_PROOF'));
    const noFailedProofs = !this.bundle.formal_proofs.some(f => f.classification !== 'CLAIM_ONLY' && !f.checked);
    const replayMatched = this.bundle.replay_results.length > 0 &&
      this.bundle.replay_results.every(r => r.status === 'MATCH' && SHA256_HEX.test(r.expected_hash) && r.expected_hash === r.observed_hash);
    const sourceBound = this.bundle.source_references.length > 0;
    if (!allTestsPassed || !machineChecked || !noFailedProofs || !replayMatched || !sourceBound) {
      this.bundle.verification_status = 'FAIL';
    } else {
      // Core evidence may be complete, but oracle signatures are not configured.
      this.bundle.verification_status = 'PARTIAL';
      this.bundle.limitations.push('Cannot mark VERIFIED without trusted-key oracle signature verification.');
    }
    return this.bundle;
  }
}

const SHA256_HEX = /^[a-f0-9]{64}$/i;
