;; business-impact-calculator
;; Revenue loss estimation and instant claim processing for cyber incidents
;; Calculates business impact and processes insurance claims automatically

;; Constants
(define-constant ERR_UNAUTHORIZED (err u401))
(define-constant ERR_INVALID_POLICY_ID (err u400))
(define-constant ERR_POLICY_ALREADY_EXISTS (err u409))
(define-constant ERR_INSUFFICIENT_FUNDS (err u422))
(define-constant ERR_CLAIM_ALREADY_PROCESSED (err u408))
(define-constant ERR_NOT_FOUND (err u404))
(define-constant ERR_INVALID_AMOUNT (err u406))
(define-constant ERR_POLICY_EXPIRED (err u410))
(define-constant ERR_CLAIM_NOT_ELIGIBLE (err u412))

;; Contract owner
(define-constant CONTRACT_OWNER tx-sender)

;; Industry types for revenue calculation
(define-constant INDUSTRY_ECOMMERCE u1)
(define-constant INDUSTRY_FINANCIAL u2)
(define-constant INDUSTRY_HEALTHCARE u3)
(define-constant INDUSTRY_TECHNOLOGY u4)
(define-constant INDUSTRY_MANUFACTURING u5)
(define-constant INDUSTRY_RETAIL u6)

;; Claim status
(define-constant CLAIM_STATUS_PENDING u1)
(define-constant CLAIM_STATUS_APPROVED u2)
(define-constant CLAIM_STATUS_REJECTED u3)
(define-constant CLAIM_STATUS_PAID u4)

;; Policy status
(define-constant POLICY_STATUS_ACTIVE u1)
(define-constant POLICY_STATUS_SUSPENDED u2)
(define-constant POLICY_STATUS_EXPIRED u3)
(define-constant POLICY_STATUS_CANCELED u4)

;; Coverage types
(define-constant COVERAGE_BASIC u1)
(define-constant COVERAGE_STANDARD u2)
(define-constant COVERAGE_PREMIUM u3)
(define-constant COVERAGE_ENTERPRISE u4)

;; Time constants
(define-constant BLOCKS_PER_HOUR u144)
(define-constant BLOCKS_PER_DAY u3456)
(define-constant HOURS_PER_DAY u24)
(define-constant MICROSECOND_TO_STX u1000000) ;; 1 STX = 1,000,000 microSTX

;; Data Maps
(define-map insurance-policies
  { policy-id: (string-ascii 64) }
  {
    policy-holder: principal,
    industry-type: uint,
    coverage-type: uint,
    annual-revenue: uint,  ;; In microSTX
    hourly-revenue: uint,  ;; Calculated from annual revenue
    premium-amount: uint,  ;; Annual premium in microSTX
    coverage-limit: uint,  ;; Maximum payout per incident in microSTX
    deductible: uint,      ;; Deductible amount in microSTX
    policy-start: uint,
    policy-end: uint,
    status: uint,
    claims-count: uint,
    total-claims-paid: uint
  }
)

(define-map business-profiles
  { policy-id: (string-ascii 64) }
  {
    business-name: (string-ascii 200),
    business-size: uint,  ;; Number of employees
    critical-systems: (list 10 (string-ascii 100)),
    revenue-streams: (list 5 (string-ascii 100)),
    peak-hours: (list 12 uint),  ;; Hours of peak business activity
    seasonal-multiplier: uint,   ;; Revenue multiplier for seasonal businesses
    dependency-score: uint,      ;; How dependent on IT systems (1-100)
    recovery-time-sla: uint      ;; Expected recovery time in hours
  }
)

(define-map insurance-claims
  { claim-id: uint }
  {
    policy-id: (string-ascii 64),
    incident-id: uint,
    claimant: principal,
    claim-timestamp: uint,
    incident-start: uint,
    incident-end: (optional uint),
    downtime-hours: uint,
    estimated-loss: uint,
    calculated-payout: uint,
    actual-payout: uint,
    claim-status: uint,
    processed-by: (optional principal),
    processing-timestamp: (optional uint),
    evidence-hash: (string-ascii 64)
  }
)

(define-map claim-calculations
  { claim-id: uint }
  {
    base-hourly-loss: uint,
    peak-hour-multiplier: uint,
    industry-impact-factor: uint,
    system-criticality-score: uint,
    recovery-delay-penalty: uint,
    seasonal-adjustment: uint,
    total-gross-loss: uint,
    deductible-applied: uint,
    coverage-cap-applied: uint,
    final-payout: uint
  }
)

(define-map fund-reserves
  { reserve-type: (string-ascii 32) }
  {
    total-funds: uint,
    allocated-funds: uint,
    available-funds: uint,
    last-updated: uint,
    managed-by: principal
  }
)

(define-map authorized-adjusters
  { adjuster: principal }
  {
    adjuster-name: (string-ascii 100),
    specialization: (string-ascii 100),
    approval-limit: uint,
    total-claims-processed: uint,
    total-amount-approved: uint,
    success-rate: uint,
    authorized-by: principal,
    authorization-timestamp: uint
  }
)

;; Data Variables
(define-data-var claim-counter uint u0)
(define-data-var total-policies uint u0)
(define-data-var total-premiums-collected uint u0)
(define-data-var total-claims-paid uint u0)
(define-data-var default-deductible-rate uint u5)  ;; 5% default deductible
(define-data-var max-payout-ratio uint u80)        ;; Maximum 80% of coverage limit

;; Private Functions

;; Validate industry type
(define-private (is-valid-industry-type (industry-type uint))
  (or
    (is-eq industry-type INDUSTRY_ECOMMERCE)
    (is-eq industry-type INDUSTRY_FINANCIAL)
    (is-eq industry-type INDUSTRY_HEALTHCARE)
    (is-eq industry-type INDUSTRY_TECHNOLOGY)
    (is-eq industry-type INDUSTRY_MANUFACTURING)
    (is-eq industry-type INDUSTRY_RETAIL)
  )
)

;; Validate coverage type
(define-private (is-valid-coverage-type (coverage-type uint))
  (and (>= coverage-type COVERAGE_BASIC) (<= coverage-type COVERAGE_ENTERPRISE))
)

;; Calculate hourly revenue from annual revenue
(define-private (calculate-hourly-revenue (annual-revenue uint))
  (/ annual-revenue (* u365 HOURS_PER_DAY))
)

;; Get industry impact factor
(define-private (get-industry-impact-factor (industry-type uint))
  (if (is-eq industry-type INDUSTRY_FINANCIAL) u150
  (if (is-eq industry-type INDUSTRY_ECOMMERCE) u130
  (if (is-eq industry-type INDUSTRY_TECHNOLOGY) u120
  (if (is-eq industry-type INDUSTRY_HEALTHCARE) u110
  (if (is-eq industry-type INDUSTRY_RETAIL) u105
  u100))))) ;; Default for MANUFACTURING
)

;; Calculate peak hour multiplier
(define-private (calculate-peak-hour-multiplier (incident-hour uint) (peak-hours (list 12 uint)))
  ;; Simplified implementation - check if incident hour is in peak hours
  (if (is-some (index-of peak-hours incident-hour))
    u150  ;; 50% increase during peak hours
    u100  ;; Normal rate during off-peak hours
  )
)

;; Calculate system criticality impact
(define-private (calculate-criticality-impact (dependency-score uint) (affected-systems-count uint))
  (let
    (
      (base-multiplier (/ dependency-score u10))  ;; Convert 1-100 to 0.1-10.0
      (system-multiplier (+ u100 (* affected-systems-count u10)))  ;; 10% per affected system
    )
    (/ (* base-multiplier system-multiplier) u100)
  )
)

;; Calculate recovery delay penalty
(define-private (calculate-recovery-penalty (actual-recovery-hours uint) (sla-hours uint))
  (if (> actual-recovery-hours sla-hours)
    (let
      (
        (delay-hours (- actual-recovery-hours sla-hours))
        (penalty-rate u5)  ;; 5% penalty per hour of delay
      )
      (+ u100 (* delay-hours penalty-rate))
    )
    u100  ;; No penalty if within SLA
  )
)

;; Check if adjuster is authorized
(define-private (is-authorized-adjuster (adjuster principal))
  (is-some (map-get? authorized-adjusters { adjuster: adjuster }))
)

;; Validate claim amount against coverage limits
(define-private (apply-coverage-limits (calculated-amount uint) (coverage-limit uint) (deductible uint))
  (let
    (
      (amount-after-deductible (if (> calculated-amount deductible)
                                 (- calculated-amount deductible)
                                 u0))
      (final-amount (if (> amount-after-deductible coverage-limit)
                      coverage-limit
                      amount-after-deductible))
    )
    final-amount
  )
)

;; Public Functions

;; Create insurance policy
(define-public (create-policy
    (policy-id (string-ascii 64))
    (industry-type uint)
    (coverage-type uint)
    (annual-revenue uint)
    (coverage-limit uint)
    (policy-duration-blocks uint))
  (let
    (
      (hourly-revenue (calculate-hourly-revenue annual-revenue))
      (premium-rate (get-premium-rate coverage-type industry-type))
      (premium-amount (/ (* coverage-limit premium-rate) u100))
      (deductible (/ (* coverage-limit (var-get default-deductible-rate)) u100))
    )
    (asserts! (is-none (map-get? insurance-policies { policy-id: policy-id })) ERR_POLICY_ALREADY_EXISTS)
    (asserts! (is-valid-industry-type industry-type) ERR_INVALID_POLICY_ID)
    (asserts! (is-valid-coverage-type coverage-type) ERR_INVALID_POLICY_ID)
    (asserts! (> annual-revenue u0) ERR_INVALID_AMOUNT)
    (asserts! (> coverage-limit u0) ERR_INVALID_AMOUNT)
    
    (var-set total-policies (+ (var-get total-policies) u1))
    
    (ok (map-set insurance-policies
      { policy-id: policy-id }
      {
        policy-holder: tx-sender,
        industry-type: industry-type,
        coverage-type: coverage-type,
        annual-revenue: annual-revenue,
        hourly-revenue: hourly-revenue,
        premium-amount: premium-amount,
        coverage-limit: coverage-limit,
        deductible: deductible,
        policy-start: stacks-block-height,
        policy-end: (+ stacks-block-height policy-duration-blocks),
        status: POLICY_STATUS_ACTIVE,
        claims-count: u0,
        total-claims-paid: u0
      }
    ))
  )
)

;; Set business profile for policy
(define-public (set-business-profile
    (policy-id (string-ascii 64))
    (business-name (string-ascii 200))
    (business-size uint)
    (critical-systems (list 10 (string-ascii 100)))
    (peak-hours (list 12 uint))
    (dependency-score uint)
    (recovery-time-sla uint))
  (let
    (
      (policy (unwrap! (map-get? insurance-policies { policy-id: policy-id }) ERR_NOT_FOUND))
    )
    (asserts! (is-eq tx-sender (get policy-holder policy)) ERR_UNAUTHORIZED)
    (asserts! (and (>= dependency-score u1) (<= dependency-score u100)) ERR_INVALID_AMOUNT)
    
    (ok (map-set business-profiles
      { policy-id: policy-id }
      {
        business-name: business-name,
        business-size: business-size,
        critical-systems: critical-systems,
        revenue-streams: (list),
        peak-hours: peak-hours,
        seasonal-multiplier: u100,
        dependency-score: dependency-score,
        recovery-time-sla: recovery-time-sla
      }
    ))
  )
)

;; Submit insurance claim
(define-public (submit-claim
    (policy-id (string-ascii 64))
    (incident-id uint)
    (incident-start uint)
    (incident-end (optional uint))
    (evidence-hash (string-ascii 64)))
  (let
    (
      (claim-id (+ (var-get claim-counter) u1))
      (policy (unwrap! (map-get? insurance-policies { policy-id: policy-id }) ERR_NOT_FOUND))
      (downtime-hours (calculate-downtime-hours incident-start incident-end))
    )
    (asserts! (is-eq tx-sender (get policy-holder policy)) ERR_UNAUTHORIZED)
    (asserts! (is-eq (get status policy) POLICY_STATUS_ACTIVE) ERR_POLICY_EXPIRED)
    (asserts! (< stacks-block-height (get policy-end policy)) ERR_POLICY_EXPIRED)
    (asserts! (> downtime-hours u0) ERR_INVALID_AMOUNT)
    
    (var-set claim-counter claim-id)
    
    (ok (map-set insurance-claims
      { claim-id: claim-id }
      {
        policy-id: policy-id,
        incident-id: incident-id,
        claimant: tx-sender,
        claim-timestamp: stacks-block-height,
        incident-start: incident-start,
        incident-end: incident-end,
        downtime-hours: downtime-hours,
        estimated-loss: u0,
        calculated-payout: u0,
        actual-payout: u0,
        claim-status: CLAIM_STATUS_PENDING,
        processed-by: none,
        processing-timestamp: none,
        evidence-hash: evidence-hash
      }
    ))
  )
)

;; Process claim and calculate payout
(define-public (process-claim (claim-id uint))
  (let
    (
      (claim (unwrap! (map-get? insurance-claims { claim-id: claim-id }) ERR_NOT_FOUND))
      (policy (unwrap! (map-get? insurance-policies { policy-id: (get policy-id claim) }) ERR_NOT_FOUND))
      (business-profile (map-get? business-profiles { policy-id: (get policy-id claim) }))
      (calculated-payout (calculate-business-impact-payout claim policy business-profile))
    )
    (asserts! (is-authorized-adjuster tx-sender) ERR_UNAUTHORIZED)
    (asserts! (is-eq (get claim-status claim) CLAIM_STATUS_PENDING) ERR_CLAIM_ALREADY_PROCESSED)
    
    ;; Update claim with calculated payout
    (map-set insurance-claims
      { claim-id: claim-id }
      (merge claim {
        calculated-payout: calculated-payout,
        claim-status: CLAIM_STATUS_APPROVED,
        processed-by: (some tx-sender),
        processing-timestamp: (some stacks-block-height)
      })
    )
    
    (ok calculated-payout)
  )
)

;; Authorize adjuster
(define-public (authorize-adjuster
    (adjuster principal)
    (adjuster-name (string-ascii 100))
    (specialization (string-ascii 100))
    (approval-limit uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (is-none (map-get? authorized-adjusters { adjuster: adjuster })) ERR_POLICY_ALREADY_EXISTS)
    
    (ok (map-set authorized-adjusters
      { adjuster: adjuster }
      {
        adjuster-name: adjuster-name,
        specialization: specialization,
        approval-limit: approval-limit,
        total-claims-processed: u0,
        total-amount-approved: u0,
        success-rate: u100,
        authorized-by: tx-sender,
        authorization-timestamp: stacks-block-height
      }
    ))
  )
)

;; Helper Functions

;; Calculate downtime in hours
(define-private (calculate-downtime-hours (start-timestamp uint) (end-timestamp (optional uint)))
  (match end-timestamp
    end-time (/ (- end-time start-timestamp) BLOCKS_PER_HOUR)
    (/ (- stacks-block-height start-timestamp) BLOCKS_PER_HOUR)
  )
)

;; Get premium rate based on coverage and industry
(define-private (get-premium-rate (coverage-type uint) (industry-type uint))
  (let
    (
      (base-rate (if (is-eq coverage-type COVERAGE_BASIC) u2
                 (if (is-eq coverage-type COVERAGE_STANDARD) u3
                 (if (is-eq coverage-type COVERAGE_PREMIUM) u4
                 u5))))  ;; ENTERPRISE
      (industry-multiplier (if (is-eq industry-type INDUSTRY_FINANCIAL) u150
                          (if (is-eq industry-type INDUSTRY_TECHNOLOGY) u120
                          u100)))
    )
    (/ (* base-rate industry-multiplier) u100)
  )
)

;; Calculate comprehensive business impact payout
(define-private (calculate-business-impact-payout
    (claim { policy-id: (string-ascii 64), incident-id: uint, claimant: principal, claim-timestamp: uint, incident-start: uint, incident-end: (optional uint), downtime-hours: uint, estimated-loss: uint, calculated-payout: uint, actual-payout: uint, claim-status: uint, processed-by: (optional principal), processing-timestamp: (optional uint), evidence-hash: (string-ascii 64) })
    (policy { policy-holder: principal, industry-type: uint, coverage-type: uint, annual-revenue: uint, hourly-revenue: uint, premium-amount: uint, coverage-limit: uint, deductible: uint, policy-start: uint, policy-end: uint, status: uint, claims-count: uint, total-claims-paid: uint })
    (business-profile (optional { business-name: (string-ascii 200), business-size: uint, critical-systems: (list 10 (string-ascii 100)), revenue-streams: (list 5 (string-ascii 100)), peak-hours: (list 12 uint), seasonal-multiplier: uint, dependency-score: uint, recovery-time-sla: uint })))
  (let
    (
      (base-loss (* (get hourly-revenue policy) (get downtime-hours claim)))
      (industry-factor (get-industry-impact-factor (get industry-type policy)))
      (adjusted-loss (/ (* base-loss industry-factor) u100))
      (final-payout (apply-coverage-limits adjusted-loss (get coverage-limit policy) (get deductible policy)))
    )
    final-payout
  )
)

;; Read-only Functions

;; Get policy details
(define-read-only (get-policy (policy-id (string-ascii 64)))
  (map-get? insurance-policies { policy-id: policy-id })
)

;; Get claim details
(define-read-only (get-claim (claim-id uint))
  (map-get? insurance-claims { claim-id: claim-id })
)

;; Get business profile
(define-read-only (get-business-profile (policy-id (string-ascii 64)))
  (map-get? business-profiles { policy-id: policy-id })
)

;; Get adjuster info
(define-read-only (get-adjuster-info (adjuster principal))
  (map-get? authorized-adjusters { adjuster: adjuster })
)

;; Get claim counter
(define-read-only (get-claim-counter)
  (var-get claim-counter)
)

;; Get total policies count
(define-read-only (get-total-policies)
  (var-get total-policies)
)

;; Calculate estimated payout for a potential claim
(define-read-only (estimate-claim-payout (policy-id (string-ascii 64)) (downtime-hours uint))
  (match (map-get? insurance-policies { policy-id: policy-id })
    policy (let
      (
        (base-loss (* (get hourly-revenue policy) downtime-hours))
        (industry-factor (get-industry-impact-factor (get industry-type policy)))
        (adjusted-loss (/ (* base-loss industry-factor) u100))
      )
      (some (apply-coverage-limits adjusted-loss (get coverage-limit policy) (get deductible policy)))
    )
    none
  )
)
