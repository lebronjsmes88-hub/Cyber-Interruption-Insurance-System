;; cyber-incident-detector
;; Integration with security monitoring tools and threat intelligence feeds
;; Detects and validates cyber incidents for insurance claim processing

;; Constants
(define-constant ERR_UNAUTHORIZED (err u401))
(define-constant ERR_INVALID_INCIDENT_TYPE (err u400))
(define-constant ERR_INCIDENT_ALREADY_REPORTED (err u409))
(define-constant ERR_INSUFFICIENT_EVIDENCE (err u422))
(define-constant ERR_INVALID_SEVERITY (err u403))
(define-constant ERR_NOT_FOUND (err u404))
(define-constant ERR_VALIDATION_FAILED (err u406))

;; Contract owner
(define-constant CONTRACT_OWNER tx-sender)

;; Incident types
(define-constant INCIDENT_TYPE_DDOS u1)
(define-constant INCIDENT_TYPE_RANSOMWARE u2)
(define-constant INCIDENT_TYPE_SYSTEM_OUTAGE u3)
(define-constant INCIDENT_TYPE_DATA_BREACH u4)
(define-constant INCIDENT_TYPE_MALWARE u5)

;; Severity levels
(define-constant SEVERITY_LOW u1)
(define-constant SEVERITY_MEDIUM u2)
(define-constant SEVERITY_HIGH u3)
(define-constant SEVERITY_CRITICAL u4)

;; Validation status
(define-constant VALIDATION_PENDING u0)
(define-constant VALIDATION_CONFIRMED u1)
(define-constant VALIDATION_REJECTED u2)

;; Data Maps
(define-map incidents
  { incident-id: uint }
  {
    reporter: principal,
    incident-type: uint,
    severity: uint,
    timestamp: uint,
    affected-systems: (list 10 (string-ascii 50)),
    evidence-hash: (string-ascii 64),
    validation-status: uint,
    validator: (optional principal),
    validation-timestamp: (optional uint),
    metadata: (string-ascii 500)
  }
)

(define-map threat-intelligence
  { source-id: (string-ascii 32) }
  {
    source-name: (string-ascii 100),
    reliability-score: uint,
    last-updated: uint,
    is-active: bool,
    registered-by: principal
  }
)

(define-map security-monitors
  { monitor-id: (string-ascii 32) }
  {
    monitor-name: (string-ascii 100),
    monitor-type: (string-ascii 50),
    endpoint: (string-ascii 200),
    credentials-hash: (string-ascii 64),
    last-heartbeat: uint,
    is-active: bool,
    registered-by: principal
  }
)

(define-map authorized-validators
  { validator: principal }
  {
    name: (string-ascii 100),
    specialization: (string-ascii 100),
    reputation-score: uint,
    total-validations: uint,
    successful-validations: uint,
    authorized-by: principal,
    authorization-timestamp: uint
  }
)

;; Data Variables
(define-data-var incident-counter uint u0)
(define-data-var validation-threshold uint u2)
(define-data-var min-evidence-requirements uint u3)

;; Private Functions

;; Validate incident type
(define-private (is-valid-incident-type (incident-type uint))
  (or
    (is-eq incident-type INCIDENT_TYPE_DDOS)
    (is-eq incident-type INCIDENT_TYPE_RANSOMWARE)
    (is-eq incident-type INCIDENT_TYPE_SYSTEM_OUTAGE)
    (is-eq incident-type INCIDENT_TYPE_DATA_BREACH)
    (is-eq incident-type INCIDENT_TYPE_MALWARE)
  )
)

;; Validate severity level
(define-private (is-valid-severity (severity uint))
  (and
    (>= severity SEVERITY_LOW)
    (<= severity SEVERITY_CRITICAL)
  )
)

;; Validate evidence hash format (simplified check for 64-character hex string)
(define-private (is-valid-evidence-hash (hash (string-ascii 64)))
  (is-eq (len hash) u64)
)

;; Check if user is authorized validator
(define-private (is-authorized-validator (validator principal))
  (is-some (map-get? authorized-validators { validator: validator }))
)

;; Calculate incident severity score based on type and affected systems
(define-private (calculate-severity-score (incident-type uint) (affected-systems (list 10 (string-ascii 50))))
  (let
    (
      (base-score
        (if (is-eq incident-type INCIDENT_TYPE_RANSOMWARE) u100
        (if (is-eq incident-type INCIDENT_TYPE_DATA_BREACH) u90
        (if (is-eq incident-type INCIDENT_TYPE_SYSTEM_OUTAGE) u70
        (if (is-eq incident-type INCIDENT_TYPE_DDOS) u60
        u50)))) ;; Default for MALWARE
      )
      (system-multiplier (len affected-systems))
    )
    (+ base-score (* system-multiplier u5))
  )
)

;; Public Functions

;; Register new security monitor
(define-public (register-security-monitor
    (monitor-id (string-ascii 32))
    (monitor-name (string-ascii 100))
    (monitor-type (string-ascii 50))
    (endpoint (string-ascii 200))
    (credentials-hash (string-ascii 64)))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (is-none (map-get? security-monitors { monitor-id: monitor-id })) ERR_INCIDENT_ALREADY_REPORTED)
    
    (ok (map-set security-monitors
      { monitor-id: monitor-id }
      {
        monitor-name: monitor-name,
        monitor-type: monitor-type,
        endpoint: endpoint,
        credentials-hash: credentials-hash,
        last-heartbeat: stacks-block-height,
        is-active: true,
        registered-by: tx-sender
      }
    ))
  )
)

;; Register threat intelligence source
(define-public (register-threat-intelligence-source
    (source-id (string-ascii 32))
    (source-name (string-ascii 100))
    (reliability-score uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (is-none (map-get? threat-intelligence { source-id: source-id })) ERR_INCIDENT_ALREADY_REPORTED)
    (asserts! (and (>= reliability-score u1) (<= reliability-score u100)) ERR_INVALID_SEVERITY)
    
    (ok (map-set threat-intelligence
      { source-id: source-id }
      {
        source-name: source-name,
        reliability-score: reliability-score,
        last-updated: stacks-block-height,
        is-active: true,
        registered-by: tx-sender
      }
    ))
  )
)

;; Authorize incident validator
(define-public (authorize-validator
    (validator principal)
    (name (string-ascii 100))
    (specialization (string-ascii 100)))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (is-none (map-get? authorized-validators { validator: validator })) ERR_INCIDENT_ALREADY_REPORTED)
    
    (ok (map-set authorized-validators
      { validator: validator }
      {
        name: name,
        specialization: specialization,
        reputation-score: u100,
        total-validations: u0,
        successful-validations: u0,
        authorized-by: tx-sender,
        authorization-timestamp: stacks-block-height
      }
    ))
  )
)

;; Report cyber incident
(define-public (report-incident
    (incident-type uint)
    (severity uint)
    (affected-systems (list 10 (string-ascii 50)))
    (evidence-hash (string-ascii 64))
    (metadata (string-ascii 500)))
  (let
    (
      (incident-id (+ (var-get incident-counter) u1))
    )
    (asserts! (is-valid-incident-type incident-type) ERR_INVALID_INCIDENT_TYPE)
    (asserts! (is-valid-severity severity) ERR_INVALID_SEVERITY)
    (asserts! (is-valid-evidence-hash evidence-hash) ERR_INSUFFICIENT_EVIDENCE)
    (asserts! (>= (len affected-systems) (var-get min-evidence-requirements)) ERR_INSUFFICIENT_EVIDENCE)
    
    (var-set incident-counter incident-id)
    
    (ok (map-set incidents
      { incident-id: incident-id }
      {
        reporter: tx-sender,
        incident-type: incident-type,
        severity: severity,
        timestamp: stacks-block-height,
        affected-systems: affected-systems,
        evidence-hash: evidence-hash,
        validation-status: VALIDATION_PENDING,
        validator: none,
        validation-timestamp: none,
        metadata: metadata
      }
    ))
  )
)

;; Validate incident
(define-public (validate-incident (incident-id uint) (validation-result uint))
  (let
    (
      (incident (unwrap! (map-get? incidents { incident-id: incident-id }) ERR_NOT_FOUND))
      (validator-info (unwrap! (map-get? authorized-validators { validator: tx-sender }) ERR_UNAUTHORIZED))
    )
    (asserts! (is-authorized-validator tx-sender) ERR_UNAUTHORIZED)
    (asserts! (is-eq (get validation-status incident) VALIDATION_PENDING) ERR_VALIDATION_FAILED)
    (asserts! (or (is-eq validation-result VALIDATION_CONFIRMED) (is-eq validation-result VALIDATION_REJECTED)) ERR_INVALID_SEVERITY)
    
    ;; Update incident with validation result
    (map-set incidents
      { incident-id: incident-id }
      (merge incident {
        validation-status: validation-result,
        validator: (some tx-sender),
        validation-timestamp: (some stacks-block-height)
      })
    )
    
    ;; Update validator statistics
    (map-set authorized-validators
      { validator: tx-sender }
      (merge validator-info {
        total-validations: (+ (get total-validations validator-info) u1),
        successful-validations: 
          (if (is-eq validation-result VALIDATION_CONFIRMED)
            (+ (get successful-validations validator-info) u1)
            (get successful-validations validator-info)
          )
      })
    )
    
    (ok validation-result)
  )
)

;; Update monitor heartbeat
(define-public (update-monitor-heartbeat (monitor-id (string-ascii 32)))
  (let
    (
      (monitor (unwrap! (map-get? security-monitors { monitor-id: monitor-id }) ERR_NOT_FOUND))
    )
    (asserts! (is-eq tx-sender (get registered-by monitor)) ERR_UNAUTHORIZED)
    
    (ok (map-set security-monitors
      { monitor-id: monitor-id }
      (merge monitor { last-heartbeat: stacks-block-height })
    ))
  )
)

;; Read-only Functions

;; Get incident details
(define-read-only (get-incident (incident-id uint))
  (map-get? incidents { incident-id: incident-id })
)

;; Get threat intelligence source
(define-read-only (get-threat-intelligence-source (source-id (string-ascii 32)))
  (map-get? threat-intelligence { source-id: source-id })
)

;; Get security monitor
(define-read-only (get-security-monitor (monitor-id (string-ascii 32)))
  (map-get? security-monitors { monitor-id: monitor-id })
)

;; Get validator info
(define-read-only (get-validator-info (validator principal))
  (map-get? authorized-validators { validator: validator })
)

;; Get incident counter
(define-read-only (get-incident-counter)
  (var-get incident-counter)
)

;; Check if incident is validated
(define-read-only (is-incident-validated (incident-id uint))
  (match (map-get? incidents { incident-id: incident-id })
    incident (is-eq (get validation-status incident) VALIDATION_CONFIRMED)
    false
  )
)

;; Get incidents by reporter
(define-read-only (get-reporter-incident-count (reporter principal))
  ;; This is a simplified implementation - in practice, you'd maintain a separate map
  ;; for efficient querying of incidents by reporter
  u0  ;; Placeholder return value
)
