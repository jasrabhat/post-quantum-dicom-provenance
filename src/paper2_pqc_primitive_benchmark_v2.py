#!/usr/bin/env python3
"""Primitive-level microbenchmark for Paper 2 ML-KEM-768 and ML-DSA-65. Correctly distinguishes API raw private-key seed representations from standardized full key encodings.

Uses the same cryptography APIs as the Paper 2 Phase A v4 harness.
Reports operation timing distributions, sizes, package/Python versions, and correctness.
This is a local microbenchmark, not a protocol-level or comparative benchmark.
"""
from __future__ import annotations
import argparse, csv, json, platform, statistics, sys, time
from pathlib import Path

try:
    import cryptography
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
except Exception as exc:
    print("Could not import ML-KEM-768 / ML-DSA-65 APIs. This script requires a compatible cryptography build (the Phase A environment used cryptography 50.0.2).", file=sys.stderr)
    print(f"Import error: {type(exc).__name__}: {exc}", file=sys.stderr)
    raise SystemExit(2)

KEM_ITERATIONS_DEFAULT = 500
SIGN_ITERATIONS_DEFAULT = 500
KEYGEN_ITERATIONS_DEFAULT = 100
CONTEXT = b"Paper2-Primitive-Benchmark-v1"
MESSAGE = b"Paper 2 ML-DSA-65 primitive benchmark message; no patient data."


def timed_samples(fn, n):
    vals=[]
    for _ in range(n):
        t0=time.perf_counter_ns(); fn(); t1=time.perf_counter_ns()
        vals.append((t1-t0)/1e6)
    return vals


def summary(vals):
    xs=sorted(vals); n=len(xs)
    # Nearest-rank empirical percentile, transparent for small benchmark samples.
    p95=xs[max(0, __import__('math').ceil(0.95*n)-1)]
    return {"n":n,"mean_ms":statistics.mean(xs),"median_ms":statistics.median(xs),
            "stdev_sample_ms":statistics.stdev(xs) if n>1 else 0.0,
            "min_ms":xs[0],"max_ms":xs[-1],"p95_nearest_rank_ms":p95}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--output-dir', required=True)
    ap.add_argument('--kem-iterations', type=int, default=KEM_ITERATIONS_DEFAULT)
    ap.add_argument('--signature-iterations', type=int, default=SIGN_ITERATIONS_DEFAULT)
    ap.add_argument('--keygen-iterations', type=int, default=KEYGEN_ITERATIONS_DEFAULT)
    ap.add_argument('--warmup', type=int, default=10)
    args=ap.parse_args()
    if min(args.kem_iterations,args.signature_iterations,args.keygen_iterations)<2 or args.warmup<0:
        ap.error('iterations must be >= 2 and warmup must be >= 0')

    out=Path(args.output_dir); out.mkdir(parents=True,exist_ok=True)
    rows=[]; metric_samples={}
    # Warm-up on independent ephemeral keys to reduce first-call/import effects.
    for _ in range(args.warmup):
        kp=MLKEM768PrivateKey.generate(); ss, ct=kp.public_key().encapsulate(); assert kp.decapsulate(ct)==ss
        sp=MLDSA65PrivateKey.generate(); sig=sp.sign(MESSAGE,CONTEXT); sp.public_key().verify(sig,MESSAGE,CONTEXT)

    metric_samples['mlkem768_keygen']=timed_samples(lambda: MLKEM768PrivateKey.generate(),args.keygen_iterations)
    kem_private=MLKEM768PrivateKey.generate(); kem_public=kem_private.public_key()
    def encapsulate_once():
        ss, ct=kem_public.encapsulate()
        if kem_private.decapsulate(ct)!=ss: raise RuntimeError('ML-KEM shared-secret mismatch')
    metric_samples['mlkem768_encapsulation_plus_correctness_check']=timed_samples(encapsulate_once,args.kem_iterations)
    # Separately time encapsulation and decapsulation with pre-generated inputs.
    kem_pairs=[]
    for _ in range(args.kem_iterations):
        ss,ct=kem_public.encapsulate(); kem_pairs.append((ss,ct))
    i={'v':0}
    def encapsulate_only():
        ss,ct=kem_public.encapsulate(); i['v']+=1
        if len(ss)!=32 or len(ct)==0: raise RuntimeError('Unexpected ML-KEM output sizes')
    metric_samples['mlkem768_encapsulation']=timed_samples(encapsulate_only,args.kem_iterations)
    def decapsulate_only():
        ss,ct=kem_pairs.pop()
        if kem_private.decapsulate(ct)!=ss: raise RuntimeError('ML-KEM decapsulation mismatch')
    metric_samples['mlkem768_decapsulation']=timed_samples(decapsulate_only,args.kem_iterations)

    metric_samples['mldsa65_keygen']=timed_samples(lambda: MLDSA65PrivateKey.generate(),args.keygen_iterations)
    signer=MLDSA65PrivateKey.generate(); verifier=signer.public_key()
    metric_samples['mldsa65_sign']=timed_samples(lambda: signer.sign(MESSAGE,CONTEXT),args.signature_iterations)
    signature=signer.sign(MESSAGE,CONTEXT)
    def verify_once(): verifier.verify(signature,MESSAGE,CONTEXT)
    metric_samples['mldsa65_verify']=timed_samples(verify_once,args.signature_iterations)

    # Sizes are obtained from the actual generated objects / serialized public keys.
    from cryptography.hazmat.primitives import serialization
    kem_pub_bytes=kem_public.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    kem_priv_bytes=kem_private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
    mldsa_pub_bytes=verifier.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    mldsa_priv_bytes=signer.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
    # Correctness checks are explicit and separate from performance claims.
    ss_check,ct_check=kem_public.encapsulate(); kem_correct=(kem_private.decapsulate(ct_check)==ss_check)
    sig_check=signer.sign(MESSAGE,CONTEXT)
    try:
        verifier.verify(sig_check,MESSAGE,CONTEXT); sig_valid=True
    except Exception:
        sig_valid=False
    tamper_rejected=False
    try: verifier.verify(sig_check,MESSAGE+b' altered',CONTEXT)
    except Exception: tamper_rejected=True

    result={
      'experiment':'Paper 2 ML-KEM-768 / ML-DSA-65 primitive microbenchmark',
      'python_version':platform.python_version(),'python_implementation':platform.python_implementation(),
      'cryptography_version':getattr(cryptography,'__version__','unknown'),
      'iterations':{'keygen':args.keygen_iterations,'kem':args.kem_iterations,'signature':args.signature_iterations,'warmup':args.warmup},
      'metrics':{k:summary(v) for k,v in metric_samples.items()},
      'api_raw_serialization_sizes_bytes':{'mlkem768_public_key':len(kem_pub_bytes),'mlkem768_private_key_raw_seed_representation':len(kem_priv_bytes),'mldsa65_public_key':len(mldsa_pub_bytes),'mldsa65_private_key_raw_seed_representation':len(mldsa_priv_bytes),'mlkem768_ciphertext':len(ct_check),'mlkem_shared_secret':len(ss_check),'mldsa65_signature':len(sig_check)},
      'standardized_full_encoding_sizes_bytes':{'mlkem768_public_key':1184,'mlkem768_decapsulation_key':2400,'mlkem768_ciphertext':1088,'mlkem_shared_secret':32,'mldsa65_public_key':1952,'mldsa65_private_key':4032,'mldsa65_signature':3309},
      'correctness':{'mlkem_shared_secret_match':kem_correct,'mldsa_signature_verifies':sig_valid,'mldsa_modified_message_rejected':tamper_rejected,'all_correctness_checks_passed':bool(kem_correct and sig_valid and tamper_rejected)},
      'limitations':['Microbenchmark only; no TLS/DICOMweb baseline.','Key-generation, encapsulation, decapsulation, signing, and verification are measured separately; no end-to-end network or storage costs.','The encapsulation-plus-correctness-check metric is an additional diagnostic and should not be compared directly with encapsulation-only timing.','Results depend on CPU, OS, Python, cryptography build, and system load.','Private-key raw serialization sizes are API seed representations, not standardized full private-key encodings; standardized full sizes are reported separately for reference.', 'No formal cryptographic validation or independent implementation audit is implied.']
    }
    with (out/'paper2_pqc_primitive_benchmark_summary.json').open('w',encoding='utf-8') as f: json.dump(result,f,indent=2)
    with (out/'paper2_pqc_primitive_benchmark_samples.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f); w.writerow(['metric','sample_index','time_ms'])
        for name,vals in metric_samples.items():
            for idx,val in enumerate(vals,1): w.writerow([name,idx,f'{val:.9f}'])
    print(json.dumps(result,indent=2))
    print(f"\nSummary JSON: {out/'paper2_pqc_primitive_benchmark_summary.json'}")
    print(f"Samples CSV: {out/'paper2_pqc_primitive_benchmark_samples.csv'}")
    if not result['correctness']['all_correctness_checks_passed']: raise SystemExit(1)

if __name__=='__main__': main()