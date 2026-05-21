This protocol natively resolves the scalability problem of multi-signature settings while preserving FAEST v2's strong post-quantum security and efficiency.

### 1. Prerequisites and Setup

- **Participants**: $n$ signers $P_j (j=1 \dots n)$, a single aggregator $Agg$ (which may be one of the signers), and a verifier $V$.
- **Message**: a common message $msg$ shared by all parties.
- **Public information**: each signer's public key $pk_j = (x_j, y_j)$, where $y_j = AES_{k_j}(x_j)$.
- **Secret information**: each signer's secret key $sk_j = k_j$.
- **Security parameter**: $\lambda = 128$.

---

### 2. Protocol Phases

### Phase 1: Collective Commitment (Collective BAVC)

The goal of this phase is to merge the random seeds of all signers into a single tree structure.

1. **Individual seed generation**: Each signer $P_j$ locally generates a root seed $r_j$ and a pre-IV $iv_{pre,j}$.
2. **Subtree construction**: Each signer expands a GGM tree from $r_j$ and sends its partial root hash (or all leaf commitments $com_{i,j}$) to the aggregator $Agg$.
3. **Tree merging**: $Agg$ builds a single large GGM tree (BAVC) whose leaves are the $n$ signers' subtrees, and computes the overall root hash $h_{com}$.
4. **Derivation of the first challenge $chall_1$**:
    - $Agg$ derives $chall_1$ by hashing the following values together.
    - $chall_1 = H(pk_1, \dots, pk_n, msg, h_{com}, iv_{pre,1}, \dots, iv_{pre,n})$
    - **Important**: To prevent key-substitution attacks, the public keys of all participants must be included in the hash input.

### Phase 2: Local Proof Generation and Masking

Each signer $P_j$ computes the intermediate data required for verification while keeping its own secret hidden.

1. **VOLE correlation generation**: After receiving $chall_1$, the signer generates the VOLE secret $u_j$ and MAC tag $V_j$ from its own tree.
2. **Witness masking**: From the secret key $k_j$, the signer constructs the extended witness $w_j$ that demonstrates satisfiability of the AES circuit, and computes the masked witness $d_j = w_j \oplus u_j$.
3. **Degree-3 constraint computation**: Following the QuickSilver v2 logic, the signer computes the coefficients $(a_{0,j}, a_{1,j}, a_{2,j})$ of every constraint polynomial arising from its AES circuit.
    - Here we apply the degree-3 optimization based on Galois theory.
4. **Transmission**: Each signer sends $(d_j, a_{0,j}, a_{1,j}, a_{2,j}, \tilde{u}_j)$ to the aggregator $Agg$.

### Phase 3: Linear Proof Aggregation

The aggregator $Agg$ physically and logically compresses the data received from the $n$ signers.

1. **Summation of polynomial coefficients**: Exploiting the additive homomorphism of QuickSilver, the polynomial coefficients are summed element-wise.
    - $\tilde{a}*{i, agg} = \sum*{j=1}^n a_{i,j}$ (for $i=0, 1, 2$)
2. **Update of $chall_2, chall_3$**: From the list of hashed VOLE secrets $\tilde{u}_j$ and $d_j$ contributed by all signers, the common $chall_2$ and $chall_3$ are derived via Fiat-Shamir.
3. **Decommitment extraction**: Based on $chall_3$, the "non-revealed paths" of the tree are identified. The common node information corresponding to the hidden index set $I$ across all signers is bundled into a single $pdecom$.
4. **Aggregate signature construction**: The final aggregate signature $\sigma_{agg}$ is output.
    - $\sigma_{agg} = (h_{com}, {d_j}*{j=1}^n, \tilde{u}*{agg}, \tilde{a}*{1, agg}, \tilde{a}*{2, agg}, pdecom, chall_3, ctr)$

### Phase 4: Batch Verification

With almost the same procedure as verifying a single signature, the verifier $V$ confirms the validity of all signers at once.

1. **Batch reconstruction of VOLE shares**: Using $h_{com}$ and $pdecom$ from $\sigma_{agg}$, the verifier batch-reconstructs the VOLE shares $Q_1, \dots, Q_n$ for all $n$ AES circuits (one per signer).
2. **Aggregate polynomial evaluation**: $V$ re-derives $chall_1, chall_2$ from all public keys ${pk_j}$ and $msg$, and uses the received aggregate coefficients $\tilde{a}_{agg}$ to check the following equality only once.
    - $\hat{a}*{0} \stackrel{?}{=} \tilde{a}*{0, agg}$
3. **Acceptance**: If the equality holds and the grinding $ctr$ is consistent with $chall_3$, the signatures of all $n$ signers are accepted.

---

### 3. Security and Performance Properties

- **Secret-key safety**: Since each signer only releases information in the form $d_j = w_j \oplus u_j$, neither the aggregator nor the verifier can recover the secret key $k_j$ (computationally, under the security of AES).
- **Substitution resistance**: Because all $pk_j$ are bound into $chall_1$, a malicious signer cannot reuse its own proof against someone else's public key.
- **Scalability**:
    - **Communication**: The hash value, polynomial coefficients, and shared challenges are all aggregated into $O(1)$. The only quantity that grows with the number of signers is the list of $d_j$.
    - **Computational cost**: Because the non-linear polynomial check is collapsed into a single evaluation, the verification time is dramatically shorter than the sum of individual verifications.
