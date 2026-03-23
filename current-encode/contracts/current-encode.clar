;; Current-Encode Identity Verification Protocol
;; Zero-knowledge identity verification with reputation staking

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-insufficient-stake (err u103))
(define-constant err-invalid-credential (err u104))
(define-constant err-credential-expired (err u105))
(define-constant err-unauthorized (err u106))

;; Minimum stake required for identity registration (in microSTX)
(define-constant min-stake-amount u1000000)

;; Data Variables
(define-data-var next-identity-id uint u1)
(define-data-var next-credential-id uint u1)
(define-data-var platform-fee-percentage uint u5) ;; 5% platform fee

;; Identity Registry
;; Stores cryptographic commitments for user identities
(define-map identities
    { identity-id: uint }
    {
        owner: principal,
        commitment-hash: (buff 32),
        stake-amount: uint,
        reputation-score: uint,
        created-at: uint,
        is-active: bool
    }
)

;; Principal to Identity mapping
(define-map principal-to-identity
    { owner: principal }
    { identity-id: uint }
)

;; Reputation Claims
;; Stores staked claims about identity attributes
(define-map reputation-claims
    { identity-id: uint, claim-type: (string-ascii 32) }
    {
        claim-value-hash: (buff 32),
        stake-amount: uint,
        validators: (list 10 principal),
        validation-count: uint,
        created-at: uint,
        expires-at: uint
    }
)

;; Verifiable Credentials
;; Time-bound context-specific identity tokens
(define-map credentials
    { credential-id: uint }
    {
        identity-id: uint,
        issuer: principal,
        credential-type: (string-ascii 32),
        credential-hash: (buff 32),
        issued-at: uint,
        expires-at: uint,
        is-revoked: bool
    }
)

;; Credential validations by third parties
(define-map credential-validations
    { credential-id: uint, validator: principal }
    {
        is-valid: bool,
        validated-at: uint
    }
)

;; Read-only functions

;; Get identity by ID
(define-read-only (get-identity (identity-id uint))
    (map-get? identities { identity-id: identity-id })
)

;; Get identity ID by principal
(define-read-only (get-identity-by-principal (owner principal))
    (map-get? principal-to-identity { owner: owner })
)

;; Get reputation claim
(define-read-only (get-reputation-claim (identity-id uint) (claim-type (string-ascii 32)))
    (map-get? reputation-claims { identity-id: identity-id, claim-type: claim-type })
)

;; Get credential
(define-read-only (get-credential (credential-id uint))
    (map-get? credentials { credential-id: credential-id })
)

;; Check if credential is valid (not expired and not revoked)
(define-read-only (is-credential-valid (credential-id uint))
    (match (map-get? credentials { credential-id: credential-id })
        credential
        (and 
            (not (get is-revoked credential))
            (>= (get expires-at credential) block-height)
        )
        false
    )
)

;; Get platform fee percentage
(define-read-only (get-platform-fee)
    (var-get platform-fee-percentage)
)

;; Public functions

;; Register new identity with cryptographic commitment
(define-public (register-identity (commitment-hash (buff 32)) (stake-amount uint))
    (let
        (
            (identity-id (var-get next-identity-id))
            (sender tx-sender)
        )
        ;; Verify minimum stake
        (asserts! (>= stake-amount min-stake-amount) err-insufficient-stake)
        
        ;; Verify identity doesn't already exist
        (asserts! (is-none (map-get? principal-to-identity { owner: sender })) err-already-exists)
        
        ;; Transfer stake to contract
        (try! (stx-transfer? stake-amount sender (as-contract tx-sender)))
        
        ;; Create identity record
        (map-set identities
            { identity-id: identity-id }
            {
                owner: sender,
                commitment-hash: commitment-hash,
                stake-amount: stake-amount,
                reputation-score: u0,
                created-at: block-height,
                is-active: true
            }
        )
        
        ;; Create principal mapping
        (map-set principal-to-identity
            { owner: sender }
            { identity-id: identity-id }
        )
        
        ;; Increment next ID
        (var-set next-identity-id (+ identity-id u1))
        
        (ok identity-id)
    )
)

;; Add reputation claim with stake
(define-public (add-reputation-claim 
    (identity-id uint) 
    (claim-type (string-ascii 32))
    (claim-value-hash (buff 32))
    (stake-amount uint)
    (duration uint))
    (let
        (
            (sender tx-sender)
            (identity (unwrap! (map-get? identities { identity-id: identity-id }) err-not-found))
        )
        ;; Verify caller owns the identity
        (asserts! (is-eq sender (get owner identity)) err-unauthorized)
        
        ;; Verify identity is active
        (asserts! (get is-active identity) err-invalid-credential)
        
        ;; Verify minimum stake
        (asserts! (>= stake-amount min-stake-amount) err-insufficient-stake)
        
        ;; Transfer stake to contract
        (try! (stx-transfer? stake-amount sender (as-contract tx-sender)))
        
        ;; Create reputation claim
        (map-set reputation-claims
            { identity-id: identity-id, claim-type: claim-type }
            {
                claim-value-hash: claim-value-hash,
                stake-amount: stake-amount,
                validators: (list),
                validation-count: u0,
                created-at: block-height,
                expires-at: (+ block-height duration)
            }
        )
        
        (ok true)
    )
)

;; Validate a reputation claim
(define-public (validate-claim (identity-id uint) (claim-type (string-ascii 32)))
    (let
        (
            (claim (unwrap! (map-get? reputation-claims 
                { identity-id: identity-id, claim-type: claim-type }) err-not-found))
            (sender tx-sender)
            (current-validators (get validators claim))
        )
        ;; Verify claim hasn't expired
        (asserts! (>= (get expires-at claim) block-height) err-credential-expired)
        
        ;; Update claim with new validator
        (map-set reputation-claims
            { identity-id: identity-id, claim-type: claim-type }
            (merge claim {
                validators: (unwrap! (as-max-len? (append current-validators sender) u10) 
                    err-invalid-credential),
                validation-count: (+ (get validation-count claim) u1)
            })
        )
        
        ;; Update reputation score
        (match (map-get? identities { identity-id: identity-id })
            identity
            (map-set identities
                { identity-id: identity-id }
                (merge identity {
                    reputation-score: (+ (get reputation-score identity) u1)
                })
            )
            false
        )
        
        (ok true)
    )
)

;; Issue verifiable credential
(define-public (issue-credential
    (identity-id uint)
    (credential-type (string-ascii 32))
    (credential-hash (buff 32))
    (duration uint))
    (let
        (
            (credential-id (var-get next-credential-id))
            (sender tx-sender)
            (identity (unwrap! (map-get? identities { identity-id: identity-id }) err-not-found))
        )
        ;; Verify identity is active
        (asserts! (get is-active identity) err-invalid-credential)
        
        ;; Create credential
        (map-set credentials
            { credential-id: credential-id }
            {
                identity-id: identity-id,
                issuer: sender,
                credential-type: credential-type,
                credential-hash: credential-hash,
                issued-at: block-height,
                expires-at: (+ block-height duration),
                is-revoked: false
            }
        )
        
        ;; Increment credential ID
        (var-set next-credential-id (+ credential-id u1))
        
        (ok credential-id)
    )
)

;; Validate credential by third party
(define-public (validate-credential (credential-id uint) (is-valid bool))
    (let
        (
            (sender tx-sender)
            (credential (unwrap! (map-get? credentials { credential-id: credential-id }) err-not-found))
        )
        ;; Verify credential hasn't expired and isn't revoked
        (asserts! (is-credential-valid credential-id) err-credential-expired)
        
        ;; Record validation
        (map-set credential-validations
            { credential-id: credential-id, validator: sender }
            {
                is-valid: is-valid,
                validated-at: block-height
            }
        )
        
        (ok true)
    )
)

;; Revoke credential (only issuer can revoke)
(define-public (revoke-credential (credential-id uint))
    (let
        (
            (sender tx-sender)
            (credential (unwrap! (map-get? credentials { credential-id: credential-id }) err-not-found))
        )
        ;; Verify caller is the issuer
        (asserts! (is-eq sender (get issuer credential)) err-unauthorized)
        
        ;; Revoke credential
        (map-set credentials
            { credential-id: credential-id }
            (merge credential { is-revoked: true })
        )
        
        (ok true)
    )
)

;; Withdraw stake (deactivates identity)
(define-public (withdraw-stake (identity-id uint))
    (let
        (
            (sender tx-sender)
            (identity (unwrap! (map-get? identities { identity-id: identity-id }) err-not-found))
            (stake-amount (get stake-amount identity))
        )
        ;; Verify caller owns the identity
        (asserts! (is-eq sender (get owner identity)) err-unauthorized)
        
        ;; Verify identity is active
        (asserts! (get is-active identity) err-invalid-credential)
        
        ;; Deactivate identity
        (map-set identities
            { identity-id: identity-id }
            (merge identity { is-active: false })
        )
        
        ;; Return stake to owner
        (as-contract (stx-transfer? stake-amount tx-sender sender))
    )
)

;; Admin function to update platform fee
(define-public (set-platform-fee (new-fee uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (asserts! (<= new-fee u100) err-invalid-credential) ;; Max 100%
        (var-set platform-fee-percentage new-fee)
        (ok true)
    )
)
