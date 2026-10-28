"""
Paper 2 â€” Merkle inclusion/consistency proof prototype.
Implements a small RFC-6962-style Merkle tree for research experiments.
Educational prototype only; not a complete RFC 9162 implementation.
"""
from pathlib import Path
import hashlib, json, csv, itertools

OUT=Path(__file__).resolve().parent / 'local_run' / 'results'

def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def leaf_hash(data: bytes) -> bytes:
    return H(b"\x00" + data)

def node_hash(left: bytes, right: bytes) -> bytes:
    return H(b"\x01" + left + right)

def tree_hash(leaves):
    n=len(leaves)
    if n==0:
        return H(b"")
    if n==1:
        return leaf_hash(leaves[0])
    k=1 << ((n-1).bit_length()-1)
    return node_hash(tree_hash(leaves[:k]), tree_hash(leaves[k:]))

def inclusion_proof(leaves, index):
    n=len(leaves)
    if not (0 <= index < n):
        raise IndexError("leaf index out of range")
    if n==1:
        return []
    k=1 << ((n-1).bit_length()-1)
    if index < k:
        return inclusion_proof(leaves[:k], index) + [tree_hash(leaves[k:])]
    return inclusion_proof(leaves[k:], index-k) + [tree_hash(leaves[:k])]

def verify_inclusion(leaf, index, size, proof, expected_root):
    if size <= 0 or index < 0 or index >= size:
        return False
    fn=index
    sn=size-1
    r=leaf_hash(leaf)
    for p in proof:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r=node_hash(p,r)
            while fn != 0 and (fn & 1)==0:
                fn >>= 1
                sn >>= 1
        else:
            r=node_hash(r,p)
        fn >>= 1
        sn >>= 1
    return r == expected_root and sn == 0

def consistency_proof(leaves, old_size):
    n=len(leaves)
    if old_size < 0 or old_size > n:
        raise ValueError("invalid old tree size")
    if old_size == 0 or old_size == n:
        return []
    return _subproof(old_size, leaves, True)

def _subproof(m, leaves, complete):
    n=len(leaves)
    if m==n:
        return [] if complete else [tree_hash(leaves)]
    k=1 << ((n-1).bit_length()-1)
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [tree_hash(leaves[k:])]
    return _subproof(m-k, leaves[k:], False) + [tree_hash(leaves[:k])]

def verify_consistency(old_size, new_size, old_root, new_root, proof):
    if old_size < 0 or new_size < old_size:
        return False
    if old_size == 0:
        return True
    if old_size == new_size:
        return old_root == new_root and len(proof)==0
    if old_size == new_size or new_size == 0:
        return False
    fn=old_size-1
    sn=new_size-1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if old_size & (old_size-1) == 0:
        fr=sr=old_root
    else:
        if not proof:
            return False
        fr=sr=proof[0]
        proof=proof[1:]
    for p in proof:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr=node_hash(p,fr)
            sr=node_hash(p,sr)
            while fn != 0 and (fn & 1)==0:
                fn >>= 1
                sn >>= 1
        else:
            sr=node_hash(sr,p)
        fn >>= 1
        sn >>= 1
    return fr==old_root and sr==new_root and sn==0

def main():
    rows=[]
    checks={}
    # Inclusion proofs for every leaf in each tree size 1..40.
    inclusion_total=0
    inclusion_pass=0
    for n in range(1,41):
        leaves=[f"manifest-{i}".encode() for i in range(n)]
        root=tree_hash(leaves)
        for i,leaf in enumerate(leaves):
            proof=inclusion_proof(leaves,i)
            ok=verify_inclusion(leaf,i,n,proof,root)
            inclusion_total += 1
            inclusion_pass += int(ok)
            rows.append({"test":"inclusion","tree_size":n,"index":i,"old_size":"",
                         "proof_length":len(proof),"valid_proof_accepted":ok,
                         "tampered_proof_rejected":"","tampered_leaf_rejected":""})
    # Consistency for every prefix size 1..n for all trees up to 40.
    consistency_total=0
    consistency_pass=0
    tamper_reject_total=0
    tamper_reject_pass=0
    for n in range(2,41):
        leaves=[f"manifest-{i}".encode() for i in range(n)]
        newroot=tree_hash(leaves)
        for m in range(1,n):
            oldroot=tree_hash(leaves[:m])
            proof=consistency_proof(leaves,m)
            ok=verify_consistency(m,n,oldroot,newroot,proof)
            consistency_total += 1
            consistency_pass += int(ok)
            badproof=list(proof)
            if badproof:
                badproof[0]=H(b"tampered")
            else:
                badproof=[H(b"tampered")]
            badok=verify_consistency(m,n,oldroot,newroot,badproof)
            tamper_reject_total += 1
            tamper_reject_pass += int(not badok)
            rows.append({"test":"consistency","tree_size":n,"index":"","old_size":m,
                         "proof_length":len(proof),"valid_proof_accepted":ok,
                         "tampered_proof_rejected":not badok,"tampered_leaf_rejected":""})
    # Tampered leaf check using one example.
    leaves=[f"manifest-{i}".encode() for i in range(8)]
    root=tree_hash(leaves)
    proof=inclusion_proof(leaves,3)
    leaf_tamper=not verify_inclusion(b"manifest-TAMPERED",3,8,proof,root)
    checks={
        "all_inclusion_proofs_pass":inclusion_total==sum(1 for r in rows if r["test"]=="inclusion" and r["valid_proof_accepted"]),
        "inclusion_count":inclusion_total,
        "consistency_count":consistency_total,
        "all_consistency_proofs_pass":consistency_pass==consistency_total,
        "all_tampered_consistency_proofs_rejected":tamper_reject_pass==tamper_reject_total,
        "tampered_leaf_rejected":leaf_tamper,
        "inclusion_successes":inclusion_pass,
        "consistency_successes":consistency_pass,
        "tampered_consistency_rejections":tamper_reject_pass
    }
    with open(OUT/"paper2_merkle_proofs_prototype_results.csv","w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    summary={
        "status":"small RFC-6962-style Merkle proof prototype; educational, not full RFC 9162 conformance",
        "tree_sizes_tested":"1 through 40",
        "inclusion_proofs_tested":inclusion_total,
        "consistency_proofs_tested":consistency_total,
        "tampered_consistency_proofs_tested":tamper_reject_total,
        "checks":checks,
        "all_checks_passed":(
            checks["all_inclusion_proofs_pass"] and checks["all_consistency_proofs_pass"]
            and checks["all_tampered_consistency_proofs_rejected"] and checks["tampered_leaf_rejected"]
        ),
        "limitations":[
            "This code is a research prototype and has not been independently audited.",
            "It does not implement all RFC 9162 details, signatures, gossip, witness persistence, or checkpoint policy.",
            "Passing local tests does not establish production security or full RFC compliance."
        ]
    }
    with open(OUT/"paper2_merkle_proofs_prototype_summary.json","w",encoding="utf-8") as f:
        json.dump(summary,f,indent=2)
    print(json.dumps(summary,indent=2))
    if not summary["all_checks_passed"]:
        raise SystemExit("Merkle proof checks failed")

if __name__=="__main__":
    main()
