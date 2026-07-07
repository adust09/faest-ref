We natively extend BAVC (Batch All-but-One Vector Commitments) and QuickSilver (degree-3 constraints) — the core algorithms of FAEST v2 (Shorter, Tighter, FAESTer) — to define a rigorous and secure 5-round aggregate signature protocol in which multiple signers collaboratively produce a signature on the same message.

The protocol is designed so that challenge synchronization is strictly enforced in order for QuickSilver's polynomial aggregation (amortization) to work correctly, eliminating any security degradation that shortcuts would introduce.

---

### FAEST v2 Native Aggregate Signature Protocol (5-Round Construction)

#### 1. Prerequisites
*   **Common message**: $msg$
*   **Participants**: signers $P_1, \dots, P_n$ and an aggregator $Agg$ that orchestrates aggregation (one of the signers may take on this role).
*   **Public keys**: $pk_j = (x_j, y_j)$ for each signer, where $y_j = E_{k_j}(x_j)$.
*   **Secret keys**: $sk_j = k_j$ for each signer.
*   **Security parameter**: $\lambda = 128$.

---

#### 2. Protocol Steps

### Round 1: Collective Commitment (Collective BAVC)
**Goal: Combine the seed information of all signers and fix a single root hash.**

1.  **Signer $P_j$**:
    *   Locally generate a root seed $r_j$ and a pre-IV $iv_{pre, j}$.
    *   Build its own subtree (a portion of the GGM tree) and send the hash of its leaf commitments to the aggregator.
2.  **Aggregator $Agg$**:
    *   Compute the root hash $h_{com}$ of a single large GGM tree (BAVC) that contains every signer's subtree.
    *   Hash all participants' public keys, the message, the root hash, and all pre-IVs together to derive the first challenge $chall_1$.
    *   Distribute $h_{com}$ and $chall_1$ to all signers.
    *   **Security**: Including every public key in $chall_1$ completely prevents key-substitution attacks.

### Round 2: Witness Masking and VOLE Hash Presentation
**Goal: Allow signers to provide the aggregator with the intermediate data required for verification while keeping their secret keys hidden.**

1.  **Signer $P_j$**:
    *   Using the received $chall_1$, generate the VOLE correlation (secret $u_j$, tag $V_j$).
    *   Build the extended witness $w_j$ from the secret key $k_j$ and compute the masked witness $d_j = w_j \oplus u_j$.
    *   Compute the VOLE consistency-check hashes $\tilde{u}_j, \tilde{V}_j$.
    *   Send $(d_j, \tilde{u}_j, \tilde{V}_j)$ to the aggregator.
2.  **Aggregator $Agg$**:
    *   Collect $d_j, \tilde{u}_j, \tilde{V}_j$ from every signer and derive the second challenge $chall_2$ by hashing them as input.
    *   Distribute $chall_2$ to all signers.

### Round 3: Additive Aggregation of QuickSilver Constraints
**Goal: Have all signers generate their proof polynomials using the same weighting coefficients so that aggregation becomes possible.**

1.  **Signer $P_j$**:
    *   Using the random coefficients derived from $chall_2$, evaluate the degree-3 constraints of its own AES circuit.
    *   Following the QuickSilver v2 logic, compute the three weighted polynomial coefficients $(a_{0,j}, a_{1,j}, a_{2,j})$.
    *   Send them to the aggregator.
2.  **Aggregator $Agg$**:
    *   Exploiting the linear homomorphism of QuickSilver, sum every signer's coefficients to produce the aggregate coefficients.
        *   $\tilde{a}_{i, agg} = \sum a_{i,j}$ (for $i=0, 1, 2$)
    *   This compresses the main part of the proof to $O(1)$, independent of the number of signers.

### Round 4: Grinding and Finalization of the Last Challenge
**Goal: Generate the final, compute-bound challenge once all data has been collected.**

1.  **Aggregator $Agg$**:
    *   Combine the aggregated proof coefficients $\tilde{a}_{agg}$ with the previous challenges and run grinding with a counter $ctr$.
    *   Repeat the computation until the trailing bits of the hash value are zero for the specified number of bits, fixing the final challenge $chall_3$.
    *   Notify all signers of the successful $chall_3$ and $ctr$.

### Round 5: Generation of the Partial Decommitment (Punctured Path)
**Goal: Based on the final challenge, reveal the tree while keeping the unnecessary seed information hidden.**

1.  **Signer $P_j$**:
    *   Using the "hidden index" obtained by decoding $chall_3$, extract the nodes within its own subtree that need to be revealed (the decommitment information $pdecom_j$).
    *   Send them to the aggregator.
2.  **Aggregator $Agg$**:
    *   Combine the $pdecom_j$ values from all signers and assemble the final aggregate signature $\sigma_{agg}$.
    *   **Signature structure**: $\sigma_{agg} = (h_{com}, \{d_j\}, \tilde{u}_{agg}, \tilde{a}_{1, agg}, \tilde{a}_{2, agg}, pdecom, chall_3, ctr)$

---

#### 3. Verification Process (Batch Verification)
The verifier checks the validity of all signatures at once with the following procedure.

1.  **Challenge reconstruction**: Recompute $chall_1, chall_2$ from all public keys, the message, $h_{com}$ contained in the signature, etc.
2.  **Batch reconstruction of VOLE shares**: From $h_{com}$, $pdecom$, and $chall_3$, batch-reconstruct the VOLE shares $Q_1, \dots, Q_n$ for all $n$ AES circuits (one per signer).
3.  **Single equality check**: Using the reconstructed shares and the aggregate coefficients $\tilde{a}_{agg}$, evaluate the following verification equation just once.
    *   $\hat{a}_0 \stackrel{?}{=} \tilde{a}_{0, agg}$
4.  If this equality holds, FAEST v2's security guarantees, on a logical level, that every signer used a correct secret key to sign the same message.

---

#### 4. Security and Efficiency Properties
*   **Full secrecy of the secret key**: Each signer only externalizes the VOLE-masked witness $d_j$ and the hashed polynomial coefficients, so the secret key $k_j$ remains completely hidden even from the aggregator.
*   **Communication efficiency**: The hashes, polynomial coefficients, and challenges are aggregated to a constant size ($O(1)$). The only quantities that grow with the number of signers are the list of $d_j$ and part of the tree opening path ($O(n)$), making the total size dramatically smaller than signing individually.
*   **Strict ordering**: By adopting a 5-round construction that fixes $chall_2$ only after the $d_j$ values are collected, native aggregation is achieved without breaking the QuickSilver security-proof framework.
