# Haveno Trade Protocol — Technical Reference

> **Purpose.** This document is a detailed, code-grounded specification of Haveno's
> trade protocol, written to serve as a basis for security audits. It describes the
> message flow, cryptographic checks, state machine, fund flow, trust model, and the
> resilience machinery, with references to the exact source files and (where useful)
> line numbers.
>
> **Scope.** The core trade protocol in `core/src/main/java/haveno/core/trade`, i.e.
> the multisig `MULTISIG_2_3` protocol: trade initiation, escrow setup, the payment
> handshake, payout, and the dispute/mediation payout paths. It does *not* cover
> offer book distribution, the P2P/Tor network layer, account-age-witness signing
> beyond its use in-trade, or wallet/daemon internals except where the protocol
> depends on them.
>
> **Baseline.** Written against commit `7a6ef17d` (branch `master`). Line numbers are
> guidance, not contract; verify against the tree you are auditing.
>
> **A note on trust.** Statements in the "Observations for auditors" section are
> labelled by confidence. Nothing in this document should be read as a confirmed
> vulnerability unless it explicitly traces an exploit path. The precise coverage
> statements ("X is verified against Y", "Z is trusted") are the useful part.

---

## 1. Roles, escrow, and the trust model

### 1.1 Roles

Every trade has exactly three participants, each identified by a `PubKeyRing`
(a signing key pair + an encryption key pair, `common/crypto/PubKeyRing`):

| Role | Meaning |
|------|---------|
| **Maker** | Created the offer. |
| **Taker** | Took the offer. |
| **Arbitrator** | Third multisig participant; resolves disputes. Chosen by the maker when signing the offer and re-validated by the taker. |

Orthogonally, one trader is the **buyer** (of XMR) and the other the **seller**,
fixed by the offer direction. The four concrete role classes combine these:
`BuyerAsMakerTrade`, `BuyerAsTakerTrade`, `SellerAsMakerTrade`, `SellerAsTakerTrade`,
plus `ArbitratorTrade`. Each has a matching protocol class
(`{Buyer,Seller}As{Maker,Taker}Protocol`, `ArbitratorProtocol`).

The buyer sends fiat/crypto **off-platform**; Haveno only escrows and moves the XMR.

### 1.2 The 2-of-3 multisig escrow

Funds are held in a Monero **2-of-3 multisig wallet** whose participants are the
maker, taker, and arbitrator (`ProcessInitMultisigRequest`). Any two of the three
can move funds. Consequences:

- **Cooperative close (happy path):** buyer and seller (the two traders) co-sign the
  payout. The arbitrator is not involved.
- **Dispute close:** the arbitrator + one trader co-sign. This is why the arbitrator
  can enforce an outcome even if the losing trader refuses to sign — but *also* why
  the arbitrator colluding with one trader is the fundamental trust assumption
  (see §1.3).
- No single party — including the arbitrator alone — can move funds.

Both traders lock a **security deposit** in addition to (for the seller) the trade
amount. The deposit is the economic incentive to follow the protocol; a
misbehaving trader can be penalized up to `PENALTY_FEE_PCT` (25%) of their deposit
in arbitration (`HavenoUtils.PENALTY_FEE_PCT`).

### 1.3 Trust model (explicit)

**Trustless between the two traders.** Neither trader can move escrow funds without
either the other trader's signature or the arbitrator's. Each trader independently
verifies every tx that touches escrow against the signed contract (see §6, §7).

**The arbitrator is trusted for:**

- **Fair dispute resolution.** In a dispute the arbitrator decides the payout split
  and co-signs it. The arbitrator colluding with a trader (or being that trader) can
  direct the *entire* escrow to the addresses in the contract — but **only** to the
  buyer/seller payout addresses recorded in the signed contract, and it must release
  the whole balance (`verifyPayoutTx`, §7.3). So the arbitrator cannot send funds to
  an arbitrary third address; the risk is an unfair *split* between the two
  contract parties, not theft to an outside wallet.
- **Security-deposit accounting on relay.** The arbitrator computes the final
  buyer/seller security-deposit amounts (net of mining fee) and returns them in
  `DepositResponse` (`ArbitratorProcessDepositRequest`). Traders consume these
  values. Each trader *does* independently verify its own reserve/deposit tx amounts
  (§3, §6), so this is mostly a convenience/agreement value, but auditors should
  confirm no trader-side decision trusts the peer's deposit figure without
  independent verification.
- **Relaying deposit txs.** The arbitrator submits and relays both deposit txs
  atomically (§6). It can censor (refuse to relay) but a partial relay is guarded:
  both txs are submitted "do-not-relay" first, then relayed together, and flushed
  on error.
- **Assigning the trade fee address** when `ARBITRATOR_ASSIGNS_TRADE_FEE_ADDRESS`
  is `true` (it is), via `InitMultisigRequest.tradeFeeAddress`.
- **Setting the final trade price** within the offer's price tolerance
  (`ProcessInitTradeRequest`, `verifyTradePrice`).

**The Monero daemon is trusted by the arbitrator** to be "trusted, unrestricted":
tx verification submits candidate txs to the pool and flushes them
(`XmrWalletService.verifyTradeTx`); `flushTxPool` requires an unrestricted RPC
(explicit error at `verifyTradeTx` if `flush_txpool` returns `-32601`).

**Not trusted / independently verified:** trade amount, trade price (within
tolerance), payout addresses, deposit amounts of *self*, contract contents, all
peer signatures, miner fees (within tolerance), payout splits (against the signed
contract or signed dispute result).

---

## 2. Cryptographic primitives

### 2.1 Keys and signatures

- Each participant holds a `KeyRing` (`common/crypto/KeyRing`) with a **signature**
  key pair and an **encryption** key pair. The public halves form the `PubKeyRing`
  exchanged in messages.
- Application-level signatures use `Sig.sign`/`Sig.verify` via the helpers
  `HavenoUtils.sign(...)` / `HavenoUtils.verifySignature(...)` /
  `HavenoUtils.isSignatureValid(...)` (`HavenoUtils.java:396–440`).
- All trade P2P messages are additionally sent **encrypted and sender-authenticated**
  through `P2PService.sendEncryptedDirectMessage` (or the mailbox equivalent for
  offline peers). The decrypted message carries the sender's signature public key,
  which the protocol matches against the trade's known pub key rings
  (`TradeProtocol.isPubKeyValid`, `onDirectMessage`). This is the *transport*
  authentication layer, distinct from the *application* signatures below.

### 2.2 Message signing by JSON canonicalization

Several application-level signatures are computed over the **JSON serialization of a
message with its own signature field nulled out**:

```
verifyPaymentSentMessage / verifyPaymentReceivedMessage   (HavenoUtils.java:471–521)
  signature   = message.getBuyer/SellerSignature()
  message.setSignature(null)
  unsignedJson = JsonUtil.objectToJson(message)
  message.setSignature(signature)          // restore
  isSignatureValid(peerPubKeyRing, unsignedJson, signature)
```

Key implications for auditors:

- The signature covers exactly the JSON-serialized fields. Fields annotated
  `@JsonExclude` are **outside** the signature. In `PaymentReceivedMessage` the
  `signerChain` field is `@JsonExclude` (and `@EqualsAndHashCode.Exclude`) —
  intentionally, so it can be added without breaking backward-compatible
  verification. See §8 (Observation O1) for the analysis of why this is safe.
- Signature verification therefore depends on **deterministic JSON serialization**
  matching between signer and verifier (`JsonUtil.objectToJson`, Gson-based). Field
  ordering and formatting must be stable across versions/JVMs. This is a standard
  canonicalization assumption worth an auditor's attention.
- The contract is signed the same way: `contractAsJson = JsonUtil.objectToJson(contract)`,
  then `HavenoUtils.sign(keyRing, contractAsJson)` (`ProcessSignContractRequest:92–93`).
  `Contract` marks `makerPubKeyRing`/`takerPubKeyRing` `@JsonExclude`, so the contract
  signature does **not** cover the pub key rings directly (they are pinned separately
  during init and carried in the contract's proto form).

### 2.3 Offer signing

The arbitrator signs the offer payload (`HavenoUtils.signOffer` /
`isArbitratorSignatureValid`, `HavenoUtils.java:449–462`) over
`offer.getSignatureHash()`. The taker checks this before taking. (Offer
construction/distribution is out of scope here but the arbitrator binding it
establishes originates in the offer.)

---

## 3. Trade lifecycle and state machine

State is held on `Trade` (`Trade.java`). There are **five** independent state
dimensions, each a monotonic enum (transitions only move forward — see
`isValidTransitionTo`):

### 3.1 `Phase` (coarse trade progress) — `Trade.java:271`

```
INIT → DEPOSIT_REQUESTED → DEPOSITS_PUBLISHED → DEPOSITS_CONFIRMED
     → DEPOSITS_UNLOCKED → DEPOSITS_FINALIZED → PAYMENT_SENT → PAYMENT_RECEIVED
```

`Phase.isValidTransitionTo(new)` = `new.ordinal() > this.ordinal()` (may skip
phases; some phases are role-specific).

### 3.2 `State` (fine-grained) — `Trade.java:195`

Each `State` belongs to a `Phase`. A state change is allowed only if the target
phase is the same phase or a valid forward phase transition
(`State.isValidTransitionTo`). Notable states, grouped by phase:

- **INIT:** `PREPARATION`, `MULTISIG_PREPARED`, `MULTISIG_MADE`,
  `MULTISIG_EXCHANGED`, `MULTISIG_COMPLETED`, `CONTRACT_SIGNATURE_REQUESTED`,
  `CONTRACT_SIGNED`.
- **DEPOSIT_REQUESTED:** `SENT_PUBLISH_DEPOSIT_TX_REQUEST`,
  `SAW_ARRIVED_PUBLISH_DEPOSIT_TX_REQUEST`, `PUBLISH_DEPOSIT_TX_REQUEST_FAILED`, …
- **DEPOSITS_PUBLISHED:** `ARBITRATOR_PUBLISHED_DEPOSIT_TXS`,
  `DEPOSIT_TXS_SEEN_IN_NETWORK`.
- **DEPOSITS_CONFIRMED / UNLOCKED / FINALIZED:** blockchain-driven.
- **PAYMENT_SENT:** `BUYER_CONFIRMED_PAYMENT_SENT`, `BUYER_SENT_PAYMENT_SENT_MSG`,
  `SELLER_RECEIVED_PAYMENT_SENT_MSG`, …
- **PAYMENT_RECEIVED:** `SELLER_CONFIRMED_PAYMENT_RECEIPT`,
  `SELLER_SENT_PAYMENT_RECEIVED_MSG`, `BUYER_RECEIVED_PAYMENT_RECEIVED_MSG`, …

Most protocol handlers gate on phase/state via the `FluentProtocol` `expect(...)`
condition (see §4), and use `setStateIfValidTransitionTo(...)` to advance.

### 3.3 `PayoutState` — `Trade.java:297`

```
PAYOUT_UNPUBLISHED → PAYOUT_PUBLISHED → PAYOUT_CONFIRMED → PAYOUT_UNLOCKED → PAYOUT_FINALIZED
```
Tracks the payout tx independently of the main `State`, because payout can be driven
by either trader, mailbox reprocessing, or a dispute.

### 3.4 `DisputeState` — `Trade.java:317`

```
NO_DISPUTE → DISPUTE_PREPARING → DISPUTE_REQUESTED → DISPUTE_OPENED
           → ARBITRATOR_{SENT,SEND_FAILED,STORED_IN_MAILBOX,SAW_ARRIVED}_DISPUTE_CLOSED_MSG
           → DISPUTE_CLOSED
  (+ mediation:  MEDIATION_REQUESTED / STARTED_BY_PEER / CLOSED)
  (+ refund:     REFUND_REQUESTED / REQUEST_STARTED_BY_PEER / REQUEST_CLOSED)
```

### 3.5 `TradePeriodState` — `Trade.java:377`

`FIRST_HALF → SECOND_HALF → TRADE_PERIOD_OVER` (drives max trade duration / when
disputes may be opened).

---

## 4. Protocol engine: `FluentProtocol`, tasks, and threading

The protocol is a **state-gated task pipeline**. Understanding this machinery is a
prerequisite for auditing the message handlers.

- **`TradeProtocol`** (abstract, `protocol/TradeProtocol.java`) is the base for all
  role protocols and implements `DecryptedDirectMessageListener` /
  `DecryptedMailboxListener`. It dispatches incoming messages by type
  (`handle(...)`, lines 149–165).
- **`FluentProtocol`** (`protocol/FluentProtocol.java`) expresses a guard + pipeline:
  ```
  expect(<Condition: phase/state + expected message + expected sender>)
    .setup(tasks(TaskA.class, TaskB.class, ...).using(new TradeTaskRunner(...)))
    .executeTasks()
  ```
  `expect(...)` logs an error and invokes the fault handler if the condition is not
  met; `given(...)` is the same but silent on mismatch.
- **`Condition`** checks: current `Phase`/`State` (`phase`, `anyPhase`, `state`,
  `anyState`), that the message is the expected type (`with`), and that the sender
  address matches the expected peer (`from`). Preconditions can add arbitrary
  boolean guards.
- **`TradeTask`** subclasses (`protocol/tasks/*`) are the atomic steps. Each `run()`
  calls `complete()` or `failed(t)`. `TradeTaskRunner` runs them in sequence and
  invokes success/fault callbacks.
- **Threading & locking.** Handlers run on a per-trade thread
  (`ThreadUtils.execute(..., trade.getId())`) and take `synchronized (trade.getLock())`.
  A `CountDownLatch` (`tradeLatch`, `latchTrade`/`unlatchTrade`/`awaitTradeLatch`)
  serializes message processing so a handler completes (including async sends) before
  the next runs. Wallet operations additionally lock `trade.getWalletLock()` and
  sometimes `HavenoUtils.getWalletFunctionLock()`. Auditors should scrutinize the
  interaction of these locks with the async `SendDirectMessageListener` callbacks
  that call `complete()`/`failed()` from network threads.

### 4.1 Message authentication at the dispatcher (`onDirectMessage`, lines 167–219)

Before any handler runs, `TradeProtocol.onDirectMessage` enforces:

1. `isMyMessage` — the message's offer id equals this trade's id.
2. `isPubKeyValid` — the decrypted message's signature pub key belongs to a known
   participant of this trade (arbitrator or peer; for the arbitrator protocol, maker
   or taker). **Bootstrapping exception:** returns `true` if the relevant pub key
   rings are still `null` (see Observation O2).
3. `InitTradeRequest` is explicitly *not* processed here — it bootstraps the pub key
   rings and is only handled in `TradeManager`.
4. Every other trade message requires a **verified** peer (`getVerifiedTradePeer`);
   otherwise it is dropped with a warning.
5. A `DepositResponse` is accepted **only** if it comes from the arbitrator.
6. If the sender's node address changed, it is updated only after deposits are
   requested (guards early address spoofing).

The mailbox path (`handleMailboxMessage`, lines 240–276) applies the same
verified-peer requirement and removes already-completed trades' messages.

---

## 5. Happy-path message flow

The full sequence (seller = maker example; the four role combinations are
symmetric). Arrows show the encrypted direct message; **A** = arbitrator, **M** =
maker, **T** = taker, **B** = buyer, **S** = seller.

### 5.1 Initiation — `InitTradeRequest`

Bootstraps pub key rings, node addresses, price, and reserve txs. Processed in
`TradeManager` (creates the `Trade`) and `ProcessInitTradeRequest`.

```
T → M      : InitTradeRequest (taker → maker)            TakerSendInitTradeRequestToMaker
M → A      : InitTradeRequest (maker → arbitrator)       MakerSendInitTradeRequestToArbitrator
A → T      : InitTradeRequest (arbitrator → taker)       ArbitratorSendInitTradeOrMultisigRequests
```

`InitTradeRequest` fields (`messages/InitTradeRequest.java`): trade protocol version
(must be `MULTISIG_2_3`), trade amount, trade price, payment method id, maker/taker
account & payment-account ids, **taker pub key ring**, account-age-witness signature
of the offer id, maker/taker/arbitrator node addresses, and the sender's **reserve
tx** (`reserveTxHash/Hex/Key`), payout address, and optional private-offer challenge.

`ProcessInitTradeRequest` validation (per recipient role):

- amount `> 0`, within `[offer.minAmount, offer.amount]`;
- maker/taker node addresses match the trade;
- protocol version `== MULTISIG_2_3`;
- **maker** pins the taker's pub key ring; **taker** looks up and pins the arbitrator
  from its accepted-arbitrators list (`getAcceptedArbitratorByAddress`) — rejects an
  arbitrator it does not accept;
- **arbitrator** pins maker pub key ring from the offer, taker pub key ring from the
  request, and cross-checks taker account id, amount, price, and take-offer date
  when the second (taker) request arrives;
- price within tolerance (`offer.verifyTradePrice`); the arbitrator sets the final
  price;
- account ids / payment-account ids, once set, cannot change (mismatch → exception);
- peer's `currentDate` sanity-checked (`verifyPeersCurrentDate`).

**Reserve tx verification** — `ArbitratorProcessReserveTx` + `verifyReserveTx`:
the arbitrator verifies each trader's reserve tx proves that the trader has locked
`sendTradeAmount + securityDeposit + tradeFee − penaltyFee` to the return address,
with `penaltyFee` provably sent to the **burn address**, miner fee within tolerance,
and no zero-fee tx. (Buyer-as-taker-without-deposit is exempt.)

### 5.2 Multisig wallet creation — `InitMultisigRequest`

A three-round Monero multisig handshake, each participant exchanging with the other
two (`ProcessInitMultisigRequest`, `messages/InitMultisigRequest.java`). Fields:
`preparedMultisigHex`, `madeMultisigHex`, `exchangedMultisigHex`, optional
`tradeFeeAddress`, and `tradePrice`.

Rounds (state advances `MULTISIG_PREPARED → MULTISIG_MADE → MULTISIG_EXCHANGED →
MULTISIG_COMPLETED`):

1. **prepare** → each calls `wallet.prepareMultisig()`;
2. **make** → `wallet.makeMultisig([peer1Prepared, peer2Prepared], 2, password)` once
   both peers' prepared hex is in;
3. **exchange (×2)** → `wallet.exchangeMultisigKeys(...)` for made then exchanged hex.

On completion the wallet is asserted to be `isMultisig() && isReady() && threshold==2
&& numParticipants==3` (`ProcessInitMultisigRequest:136–140`); the final multisig
address is stored in `processModel.multisigAddress`. Each incoming request's
multisig hex is reconciled against any previously received value and **must match**
(replay/tamper guard, lines 92–97). The trade fee address is adopted only when it
comes from the arbitrator.

### 5.3 Contract signing — `SignContractRequest` / `SignContractResponse`

Once multisig is complete and deposit tx hashes are known, participants exchange the
contract (`MaybeSendSignContractRequest`, `ProcessSignContractRequest`,
`messages/SignContract{Request,Response}.java`).

- `SignContractRequest` carries: deposit tx hash, account id, **payment account
  payload hash**, payout address, and (maker only) the account-age-witness signature
  of the deposit hash.
- Recipients validate the payout address (`MoneroUtils.isValidAddress` for the
  network) and record peer fields.
- **Once both traders' payment-account-payload hashes are present**, each participant
  builds the **canonical `Contract`** (`trade.createContract()`), serializes it to
  JSON, hashes it (`contractHash = SHA-256(contractAsJson)`), and **signs it**.
- Traders also generate a random symmetric key, encrypt their `PaymentAccountPayload`
  with it (`ScryptUtil` key + `Encryption.encrypt`), and send the ciphertext in
  `SignContractResponse` — the cleartext account details are revealed to the peer only
  now (and the decryption key only later, in `DepositRequest`).
- The response returns the contract JSON + signature (+ encrypted payload). State →
  `CONTRACT_SIGNED`. The arbitrator sends the response to both traders; a trader
  sends it only to its peer.

The `Contract` (`Contract.java`) binds: offer payload, amount, price, buyer/seller
node addresses, `isBuyerMakerAndSellerTaker`, both account ids, both payment method
ids (must be equal, or SEPA/SEPA-INSTANT), both payment-account-payload hashes, both
pub key rings, both payout addresses, and the maker/taker deposit tx hashes.

### 5.4 Deposit — `DepositRequest` / `DepositResponse`

```
T → A      : DepositRequest (contract signature + deposit tx)
M → A      : DepositRequest (contract signature + deposit tx)
A → M, T   : DepositResponse (after BOTH received & verified; relays deposit txs)
```

`ArbitratorProcessDepositRequest`:

- verifies each sender's **contract signature** over the arbitrator's stored
  `contractAsJson` (`isSignatureValid`);
- verifies the sender's **deposit tx** (`verifyDepositTx`): proves `tradeAmount +
  securityDeposit` locked to the **multisig address**, `tradeFee` to the trade-fee
  address, miner fee in tolerance, non-zero fee, key images match if provided;
- records the (optional) `paymentAccountKey` — the symmetric key that decrypts the
  peer's earlier-encrypted `PaymentAccountPayload`;
- **when both contract signatures are present**, submits both deposit txs to the pool
  `do-not-relay`, then relays them together (`relayTxsByHash`), flushing on failure;
  state → `ARBITRATOR_PUBLISHED_DEPOSIT_TXS`.
- `DepositResponse` (to both traders) carries the final buyer/seller security-deposit
  amounts (net of mining fee), or an error string that becomes a NACK.

The `DepositResponse` handler (`TradeProtocol.handleDepositResponse`,
`ProcessDepositResponse`) is accepted only from the arbitrator and finalizes trade
initialization for the traders.

### 5.5 Deposits confirmed — `DepositsConfirmedMessage`

When a participant's wallet sees the deposit txs confirmed, it sends
`DepositsConfirmedMessage` to the other two (`maybeSendDepositsConfirmedMessages`,
`SendDepositsConfirmedMessage*`, `ProcessDepositsConfirmedMessage`). Crucially this
carries **updated multisig hex** and (for the seller) allows exchanging the multisig
signing data needed to *create* the payout tx. It is re-sent until ACKed
(`setDepositsConfirmedAckMessage`). `VerifyPeersAccountAgeWitness` runs here.

### 5.6 Payment sent — `PaymentSentMessage` (buyer → seller, buyer → arbitrator)

After the buyer sends fiat/crypto off-platform and clicks confirm
(`BuyerProtocol.onPaymentSent`):

- `BuyerPreparePaymentSentMessage`: if the buyer has the seller's updated multisig
  hex, it **creates the unsigned payout tx** now (`trade.createPayoutTx()` →
  `doCreatePayoutTx`, §7.1) and stores `unsignedPayoutTxHex`.
- `PaymentSentMessage` (`messages/PaymentSentMessage.java`) is **signed by the buyer**
  (`buyerSignature`, verified via JSON canonicalization, §2.2) and carries the
  unsigned payout tx hex, updated multisig hex, the buyer's account-age-witness data,
  and payment metadata. Sent to seller and arbitrator; re-sent until ACKed.

Receipt (`TradeProtocol.handle(PaymentSentMessage)`, lines 617–728): only the seller
or arbitrator accept it; the buyer signature is verified **before** any processing;
duplicates are ACKed idempotently; if a payout tx already exists the message is
ignored with a fresh ACK. Then `ApplyFilter → ProcessPaymentSentMessage →
VerifyPeersAccountAgeWitness`.

### 5.7 Payment received — `PaymentReceivedMessage` (seller → buyer, seller → arbitrator)

After the seller confirms receipt (`SellerProtocol.onPaymentReceived`):

- `SellerPreparePaymentReceivedMessage`: the seller **verifies, signs, and publishes**
  the payout tx from the buyer's `unsignedPayoutTxHex`
  (`trade.processPayoutTx(hex, sign=true, publish=true)`, §7.2). If that unsigned tx
  is unusable/stale it creates a fresh unsigned payout tx and defers publication to
  the buyer.
- `PaymentReceivedMessage` (`messages/PaymentReceivedMessage.java`) is **signed by the
  seller** and carries the signed and/or unsigned payout tx hex, updated multisig hex,
  the `payoutTxId`, buyer account-age-witness + signed witness, the `signerChain`
  (see O1), a `deferPublishPayout` flag, and — importantly — **the embedded
  `PaymentSentMessage`** (so the arbitrator, who may never have received it directly,
  can validate the buyer's signature transitively). Sent to buyer and arbitrator;
  re-sent until ACKed.

Receipt (`TradeProtocol.handle(PaymentReceivedMessage)`, lines 731–855): only buyer
or arbitrator accept it; the seller signature (and the embedded buyer signature) is
verified before processing; role-specific minimum phases are enforced (buyer:
≥ PAYMENT_SENT; arbitrator: ≥ DEPOSITS_CONFIRMED; seller n/a). `ProcessPaymentReceivedMessage`
then verifies/publishes the payout (§7.2) and republishes the buyer's signed witness.

At this point the payout is on-chain: buyer receives `buyerDeposit + tradeAmount −
½fee`, seller receives `sellerDeposit − tradeAmount − ½fee`. Trade completes.

---

## 6. Reserve & deposit transaction verification (`verifyTradeTx`)

`XmrWalletService.verifyTradeTx` (`XmrWalletService.java:739`) is the single
choke-point behind both `verifyReserveTx` and `verifyDepositTx`. Given a tx hash,
hex, and tx key, it:

1. Ensures the tx is **not already in the pool** (`getTx(txHash) == null`), else
   throws "Tx is already submitted" (see Observation O3).
2. **Submits** the tx hex to the pool `do-not-relay`; requires `result.isGood()`.
3. Re-fetches the pool tx to obtain weight/size.
4. If `keyImages` supplied, the tx's input key images must **exactly** equal the
   claimed set (double-spend / input-substitution guard).
5. Requires **unlock time = 0**.
6. Verifies **miner fee** within `MINER_FEE_TOLERANCE_FACTOR` (5×) of the
   daemon's weight-based estimate (`verifyMinerFee`, `HavenoUtils.java:737`).
7. Verifies, via `checkTxKey` proofs, that the **trade fee** amount reaches the fee
   address and the **send amount** (`sendAmount − txFee`) reaches the transfer
   address — each within a 1-atomic-unit tolerance (`equalsWithinFractionError`).
8. `finally` **flushes** the tx from the pool (requires unrestricted daemon).

`verifyReserveTx` sets `sendAmount = sendTradeAmount + securityDeposit + tradeFee −
penaltyFee` and checks the `penaltyFee` reaches the **burn address**.
`verifyDepositTx` sets `sendAmount = sendTradeAmount + securityDeposit` to the
**multisig address** and checks `tradeFee` reaches the fee address. The mining fee is
subtracted from the security deposit in accounting.

---

## 7. Payout transaction construction & verification

### 7.1 Cooperative payout construction — `doCreatePayoutTx` (`Trade.java:1373`)

Built by whichever trader creates it (buyer in the happy path):

```
buyerPayoutAmount  = buyerDepositAmount + tradeAmount
sellerPayoutAmount = sellerDepositAmount − tradeAmount
destinations: [ buyerPayoutAddress: buyerPayoutAmount,
                sellerPayoutAddress: sellerPayoutAmount ]
subtractFeeFrom(0,1)        // split the miner fee between both outputs
priority = PROTOCOL_FEE_PRIORITY
```

Deposit amounts are read from the actual on-chain deposit txs
(`getSeller/Buyer().getDepositTx().getIncomingAmount()`). Payout addresses come from
the `TradePeer` records (which the contract binds).

### 7.2 Cooperative payout verification — `doProcessPayoutTx` (`Trade.java:1550`)

The counterparty (seller) verifies **before** signing/publishing:

- describes the multisig tx; requires **exactly one tx** with **exactly two
  destinations**;
- both destination addresses **equal the contract's** buyer/seller payout addresses
  (order-independent);
- expected amounts recomputed from on-chain deposits ± trade amount − ½fee, checked
  by `verifyPayoutTx` (§7.3);
- **on sign:** signs the multisig hex; for `protocolVersion ≥ 2` **recreates** the
  payout tx locally and requires the presented tx's miner fee within tolerance of the
  freshly-estimated fee (defends against a peer inflating the miner fee at the other's
  expense);
- **on publish:** submits the fully-signed multisig tx; on rejection/multisig error
  clears the recorded hex so a fresh payout can be attempted.

### 7.3 `verifyPayoutTx` invariants (`Trade.java:1790`)

Shared by cooperative and dispute payouts:

- payout tx **unlock time = 0**;
- any **change returns to the multisig wallet's own primary address** (only dust
  tolerated);
- **sum of outputs = buyerAmount + sellerAmount + change** (no hidden outputs);
- the tx **releases essentially the whole unlocked multisig balance** — at most
  `MAX_PAYOUT_TX_CHANGE` (dust) may remain (prevents leaving funds stranded or
  siphoning to a hidden output);
- each trader's amount **exactly equals** the expected amount.

### 7.4 Dispute payout — arbitrator-decided

Construction: `createDisputePayoutTx(contract, disputeResult, ...)` (`Trade.java:1416`)
uses the **contract's** payout addresses and the `DisputeResult`'s
`buyer/sellerPayoutAmountBeforeCost`, requires both ≥ 0 and their sum ≤ unlocked
balance, and configures who bears the miner fee (`subtractFeeFrom` per
`disputeResult.getSubtractFeeFrom()`, or the winner if the loser gets 0).

Trader-side verification: `doProcessDisputePayoutTx` (`Trade.java:1679`):

- requires the local dispute's `Contract` to **equal** the trade contract;
- describes the arbitrator's unsigned payout tx; 1 or 2 destinations; addresses match
  the contract;
- expected amounts = `disputeResult.buyer/sellerPayoutAmountBeforeCost − share of
  fee`, checked by `verifyPayoutTx` (§7.3, so the whole balance must be released);
- signs, then (protocol ≥ 2) recreates the dispute payout to check the miner fee is
  within tolerance;
- submits the fully-signed tx.

The `DisputeResult` is only accepted if the **arbitrator's signature** over
`Hash.getSha256Hash(disputeResult.getPayoutSignaturePayload())` verifies against the
pinned arbitrator pub key ring, and the summary text signature verifies
(`ArbitrationManager.handle(DisputeClosedMessage)`, lines 352–361). Thus a trader
will co-sign **only** the split the arbitrator actually signed, paid **only** to the
contract's addresses, releasing the whole balance.

### 7.5 Mediation payout (opt-in, cooperative)

`DisputeProtocol` handles mediation: `onAcceptMediationResult` /
`onFinalizeMediationResultPayout` and the `MediatedPayoutTxSignatureMessage` /
`MediatedPayoutTxPublishedMessage` exchange (`protocol/tasks/mediation/*`). Mediation
is non-binding: both traders must accept and co-sign; if they do not, the case can
escalate to arbitration. (Detailed mediation accounting is out of scope for this
revision — see the mediation task package.)

---

## 8. Per-message validation matrix

For each protocol message: who sends it, who accepts it, the application-level
signature (what is covered), what the recipient independently verifies, and the
state transition it drives. "Transport auth" (encryption + sender pub-key match) and
"trade id match" apply to **all** messages and are omitted from the table.

| Message | Sender → Recipient(s) | App signature | Recipient verifies | Drives |
|---|---|---|---|---|
| `InitTradeRequest` | T→M, M→A, A→T | none (transport only; reserve tx is self-proving) | version=MULTISIG_2_3; amount/price/addresses; arbitrator accepted (taker); pins pubkey rings; reserve tx via `verifyReserveTx` (arbitrator) | INIT bootstrap |
| `InitMultisigRequest` | each ↔ other two | none | multisig hex matches any prior value; fee address only from arbitrator; final wallet is 2/3 & ready | `MULTISIG_PREPARED…COMPLETED` |
| `SignContractRequest` | trader→peer(s) | none | payout address valid; records peer fields | `CONTRACT_SIGNATURE_REQUESTED` |
| `SignContractResponse` | →peer(s) | contract signature (peer's, over contract JSON) | contract JSON + signature; stores encrypted payment payload | `CONTRACT_SIGNED` |
| `DepositRequest` | M→A, T→A | contract signature (sender's) | sender contract signature; deposit tx via `verifyDepositTx`; records payment-account key | `SAW_ARRIVED…`; relays txs |
| `DepositResponse` | A→M, A→T (arbitrator only) | none (accepted only from arbitrator) | error/ack; final deposit amounts | `ARBITRATOR_PUBLISHED_DEPOSIT_TXS` / init complete |
| `DepositsConfirmedMessage` | each→other two | none | records updated multisig hex; account-age witness | resend-until-ACK; enables payout creation |
| `PaymentSentMessage` | B→S, B→A | **buyer signature** over msg JSON | buyer signature (incl. by arbitrator); phase; idempotent on dup | `BUYER_SENT…`/`SELLER_RECEIVED…` |
| `PaymentReceivedMessage` | S→B, S→A | **seller signature** over msg JSON; embeds signed `PaymentSentMessage` | seller sig + embedded buyer sig; deposits unlocked; payout via `processPayoutTx` (§7.2) | `SELLER_SENT…`/`BUYER_RECEIVED…`; payout published |
| `DisputeClosedMessage` | A→trader | **arbitrator signature** over payout payload + summary | arbitrator sig on `payoutSignaturePayload`; contract equality; payout via `doProcessDisputePayoutTx` (§7.4) | `DISPUTE_CLOSED`; dispute payout published |
| `MediatedPayoutTxSignatureMessage` / `…PublishedMessage` | trader↔trader | multisig co-signature | mediation payout tx; both must accept | mediation payout |

---

## 9. Fund-flow accounting

Let `A` = trade amount (XMR), `D_b`/`D_s` = buyer/seller security deposits (before
mining fee), `f_r`/`f_d` = reserve/deposit tx miner fees, `f_p` = payout miner fee,
`fee_t` = trade fee, `pen` = penalty portion (`PENALTY_FEE_PCT × deposit`, provably
burned in the reserve tx).

**Into escrow (multisig), per deposit tx (`verifyDepositTx`):**
- seller deposit tx locks `A + D_s` to the multisig; pays `fee_t` to fee address.
- buyer deposit tx locks `0 + D_b` to the multisig; pays `fee_t` to fee address.
- (Reserve txs, pre-escrow, additionally burn `pen` to the burn address as a
  bond; the security deposit is reduced by the tx's mining fee in accounting.)

**Multisig balance at payout ≈** `A + D_s + D_b`.

**Cooperative payout (`doCreatePayoutTx` / `verifyPayoutTx`):**
- buyer receives `D_b + A − ½f_p`
- seller receives `D_s − A − ½f_p`
- change ≤ dust; whole balance released.

**Dispute payout:** arbitrator sets `buyerPayoutAmountBeforeCost` +
`sellerPayoutAmountBeforeCost` (sum ≤ balance), fee borne per `subtractFeeFrom`; the
whole balance is still released to the two contract addresses.

**Fee bearers.** Trade fee is paid by each trader in their deposit tx to the
arbitrator-assigned fee address. Miner fee on the payout is split (or assigned by the
dispute result). The penalty (25% of deposit) is only realized against a
protocol-breaking party via arbitration.

---

## 10. Resilience, delivery, and replay considerations

- **Mailbox delivery.** Offline peers receive messages via encrypted mailbox
  (`MailboxMessageService`); on startup they are replayed in a defined order
  (`MailboxMessageComparator`) and removed after successful processing (or
  immediately if the trade is already complete).
- **Idempotent reprocessing.** `PaymentSentMessage` / `PaymentReceivedMessage` /
  `DisputeClosedMessage` are stored and reprocessed with backoff
  (`maybeReprocess…`, `REPROCESS_DELAY_MS`, `MAX_ATTEMPTS = 5`). Duplicates after
  the payout is published are ACKed without re-executing.
- **ACK/NACK.** Every trade message is answered with an `AckMessage`
  (`handleTaskRunnerSuccess/Fault`). NACKs drive recovery: e.g. a
  `PaymentReceivedMessage` NACK carries the peer's **updated multisig hex** so the
  seller can rebuild the payout (`onPaymentReceivedNack`, capped at `MAX_ATTEMPTS`);
  a maker's `InitTradeRequest` NACK from the arbitrator triggers reserve-tx recreation,
  then offer removal on a second, unacceptable NACK.
- **Timeouts.** `TRADE_STEP_TIMEOUT_SECONDS` (180s mainnet / 90s testnet) bounds
  init steps; a timeout after deposits are published does **not** fail the trade
  (funds are committed) — it just resolves the init handler.
- **Connection switching.** Wallet/daemon operations retry with connection switching
  (`handleWalletError`, `REQUEST_CONNECTION_SWITCH_EVERY_NUM_ATTEMPTS`).
- **Replay protection.** Trade messages carry an offer id (matched to the trade) and
  a per-message `uid`; multisig hex, deposit hashes, account ids, and contract fields
  are pinned on first receipt and **must match** on any subsequent message. Transport
  encryption + sender pub-key matching prevents third-party injection.

---

## 11. Observations for auditors

These are **coverage observations and questions**, labelled by confidence. They are
starting points for review, not confirmed findings.

**O1 — `signerChain` is outside the seller signature (analysed: not a finding).**
`PaymentReceivedMessage.signerChain` is `@JsonExclude`, so it is not covered by the
seller's signature and could be altered by the relaying party (in practice only the
arbitrator relays a `PaymentReceivedMessage` it did not originate). However
`SignedWitnessService.addValidSignerChain` (`SignedWitnessService.java:317`) accepts
**only** witnesses whose own signatures verify and which chain from the seller's pub
key; each `SignedWitness` is self-verifying. A forged/injected chain entry is
therefore *ignored*, not accepted. Worst case is loss of the resilience benefit
(healing a missing witness), not acceptance of an invalid witness. **Recommend
confirming** there is no downstream code that treats presence in `signerChain` as
proof of anything beyond the per-witness signature check.

**O2 — `isPubKeyValid` bootstrapping window (likely by-design; verify).**
`TradeProtocol.isPubKeyValid` (lines 1255–1280) returns `true` when the relevant pub
key rings are still `null`. This is the intended bootstrap for `InitTradeRequest`
(which is handled only in `TradeManager`, not via this path) and the earliest init
messages. Once `ProcessInitTradeRequest` pins the rings, all later messages require a
matching signature pub key, and node-address updates are refused until deposits are
requested. **Recommend confirming** that no message which mutates fund-relevant state
(reserve/deposit/contract) can be processed while the corresponding ring is still
`null` — i.e. that the pinning in `ProcessInitTradeRequest`/`ProcessInitMultisigRequest`
strictly precedes any such handler for a given peer.

**O3 — reserve/deposit verification submits a "not already in pool" candidate
(low; needs an exposure path).** `verifyTradeTx` throws "Tx is already submitted" if
the txHash is already in the arbitrator's pool. Because reserve/deposit tx hexes
travel over encrypted, sender-authenticated channels, an external party generally
cannot learn the hex to pre-submit it. **Recommend confirming** there is no path
where a tx hex is exposed before verification (e.g. logs, a shared daemon pool that
an adversary can write to), which would turn this into a verification-DoS/griefing
vector for that trade step.

**O4 — miner-fee tolerance is 5× (accounting note, low).**
`MINER_FEE_TOLERANCE_FACTOR = 5.0`. A counterparty could present a payout/deposit tx
with a miner fee up to 5× the estimate. For the payout this cost is split (or borne
per the dispute result) and comes out of amounts that are otherwise verified, so it
bounds an annoyance, not theft. Worth confirming the estimate basis (`getFeeEstimate`
weight × daemon fee) cannot be manipulated by a hostile daemon the *victim* is
connected to.

**O5 — `equalsWithinFractionError` 1-au slack (accounting note, low).**
Reserve/deposit amount and trade-fee checks tolerate a 1-atomic-unit difference to
paper over a historical unit-conversion bug. Negligible economically; flagged for
completeness. Also note `verifyPaymentAccountPayloadHash` accepts documented "legacy"
hashes for three payment-account types (a v1.2.3 compatibility shim,
`HavenoUtils.java:749`) — confirm this cannot be abused to bind a different payload.

**O6 — JSON-canonicalization dependency for all app signatures (design assumption).**
Contract, `PaymentSentMessage`, and `PaymentReceivedMessage` signatures are computed
over `JsonUtil.objectToJson(...)` with the signature field nulled. Correctness
depends on **byte-stable** JSON serialization across versions, JVMs, and locales, and
on `@JsonExclude` being applied to exactly the fields that must be outside the
signature. This is the single most load-bearing canonicalization assumption in the
protocol. **Recommend** a focused review of `JsonUtil`/Gson configuration for
determinism (field ordering, number/`BigInteger` formatting, `null` handling) and an
inventory of every `@JsonExclude` field on a signed type.

**O7 — arbitrator trust surface (design; document, don't "fix").**
As detailed in §1.3, a malicious arbitrator can, in a dispute, direct the escrow to
an **unfair split between the two contract addresses** and can censor by refusing to
relay/close. It **cannot** send to a third-party address (`verifyPayoutTx` +
contract-address binding) nor move funds without a trader's co-signature. The
security model relies on arbitrator selection/bonding and the traders' independent
verification. Audit value is in confirming those two guarantees hold on **every**
arbitrator-driven payout path (dispute close, mediation, and the resend/reprocess
variants).

**O8 — lock/callback interleaving (concurrency review target).**
Message handlers hold `trade.getLock()` and a `tradeLatch`, but several tasks
(`ProcessSignContractRequest`, `ProcessInitMultisigRequest`,
`ArbitratorProcessDepositRequest`) complete asynchronously from
`SendDirectMessageListener` callbacks on network threads, calling
`complete()`/`failed()` there. Wallet operations take additional
`walletLock`/`getWalletFunctionLock`. **Recommend** a dedicated concurrency review of
these async completions vs. the per-trade latch, and of the state subscriptions
(`EasyBind.subscribe(stateProperty…)`) that re-enter handlers on state change, for
deadlock/double-execution.

---

## 12. Appendix — file map

| Area | Key files |
|---|---|
| Protocol base / dispatch | `protocol/TradeProtocol.java`, `protocol/FluentProtocol.java`, `protocol/TradeTaskRunner.java` |
| Role protocols | `protocol/{Buyer,Seller}As{Maker,Taker}Protocol.java`, `protocol/ArbitratorProtocol.java`, `protocol/DisputeProtocol.java` |
| Trade model / state | `Trade.java`, `TradeManager.java`, `protocol/ProcessModel.java`, `protocol/TradePeer.java` |
| Contract | `Contract.java` |
| Crypto / helpers | `HavenoUtils.java` (signing, verification, fees, addresses) |
| Init & escrow tasks | `protocol/tasks/ProcessInitTradeRequest.java`, `ArbitratorProcessReserveTx.java`, `ProcessInitMultisigRequest.java`, `MaybeSendSignContractRequest.java`, `ProcessSignContractRequest.java`, `ArbitratorProcessDepositRequest.java`, `ProcessDepositResponse.java` |
| Payment/payout tasks | `protocol/tasks/BuyerPreparePaymentSentMessage.java`, `ProcessPaymentSentMessage.java`, `SellerPreparePaymentReceivedMessage.java`, `ProcessPaymentReceivedMessage.java` |
| Messages | `messages/*.java` (`InitTradeRequest`, `InitMultisigRequest`, `SignContract{Request,Response}`, `Deposit{Request,Response}`, `DepositsConfirmedMessage`, `Payment{Sent,Received}Message`, `MediatedPayoutTx*`) |
| Tx verification | `xmr/wallet/XmrWalletService.java` (`verifyTradeTx`, `verifyReserveTx`, `verifyDepositTx`) |
| Dispute / mediation | `support/dispute/arbitration/ArbitrationManager.java`, `support/dispute/DisputeManager.java`, `support/dispute/DisputeResult.java`, `protocol/tasks/mediation/*` |

---

*This reference complements the high-level [trade-protocol.md](trade-protocol.md) and
the diagram [trade-protocol.pdf](trade-protocol.pdf). Where this document and the
diagram disagree, the source code is authoritative.*
