;; downtime-measurement-oracle
;; Automated system availability monitoring and downtime quantification
;; Measures service availability and calculates precise downtime metrics

;; Constants
(define-constant ERR_UNAUTHORIZED (err u401))
(define-constant ERR_INVALID_SERVICE_ID (err u400))
(define-constant ERR_SERVICE_ALREADY_REGISTERED (err u409))
(define-constant ERR_INVALID_MEASUREMENT (err u422))
(define-constant ERR_NOT_FOUND (err u404))
(define-constant ERR_INVALID_THRESHOLD (err u406))
(define-constant ERR_MEASUREMENT_TOO_OLD (err u408))

;; Contract owner
(define-constant CONTRACT_OWNER tx-sender)

;; Service status codes
(define-constant SERVICE_STATUS_OPERATIONAL u1)
(define-constant SERVICE_STATUS_DEGRADED u2)
(define-constant SERVICE_STATUS_DOWN u3)
(define-constant SERVICE_STATUS_MAINTENANCE u4)

;; Measurement types
(define-constant MEASUREMENT_TYPE_PING u1)
(define-constant MEASUREMENT_TYPE_HTTP u2)
(define-constant MEASUREMENT_TYPE_DNS u3)
(define-constant MEASUREMENT_TYPE_DATABASE u4)
(define-constant MEASUREMENT_TYPE_API u5)

;; SLA thresholds
(define-constant SLA_THRESHOLD_99_9 u999)  ;; 99.9%
(define-constant SLA_THRESHOLD_99_5 u995)  ;; 99.5%
(define-constant SLA_THRESHOLD_99_0 u990)  ;; 99.0%
(define-constant SLA_THRESHOLD_95_0 u950)  ;; 95.0%

;; Time constants (in blocks)
(define-constant BLOCKS_PER_HOUR u144)     ;; Approximately 144 blocks per hour
(define-constant BLOCKS_PER_DAY u3456)     ;; Approximately 3456 blocks per day
(define-constant BLOCKS_PER_WEEK u24192)   ;; Approximately 24192 blocks per week
(define-constant MAX_MEASUREMENT_AGE u1440) ;; Maximum age for measurements (10 hours)

;; Data Maps
(define-map registered-services
  { service-id: (string-ascii 64) }
  {
    service-name: (string-ascii 200),
    service-url: (string-ascii 300),
    service-type: (string-ascii 50),
    measurement-interval: uint,
    sla-threshold: uint,
    registered-by: principal,
    registration-timestamp: uint,
    is-active: bool,
    last-measurement: (optional uint)
  }
)

(define-map availability-measurements
  { measurement-id: uint }
  {
    service-id: (string-ascii 64),
    timestamp: uint,
    status: uint,
    response-time: uint,
    measurement-type: uint,
    measured-by: principal,
    metadata: (string-ascii 300)
  }
)

(define-map downtime-incidents
  { incident-id: uint }
  {
    service-id: (string-ascii 64),
    start-timestamp: uint,
    end-timestamp: (optional uint),
    duration-blocks: uint,
    severity: uint,
    root-cause: (string-ascii 200),
    reported-by: principal,
    status: uint  ;; 1=ongoing, 2=resolved, 3=false-positive
  }
)

(define-map sla-compliance
  { service-id: (string-ascii 64), period-start: uint }
  {
    total-measurements: uint,
    successful-measurements: uint,
    total-downtime-blocks: uint,
    availability-percentage: uint,
    sla-breached: bool,
    last-updated: uint
  }
)

(define-map authorized-monitors
  { monitor: principal }
  {
    monitor-name: (string-ascii 100),
    monitor-location: (string-ascii 100),
    reputation-score: uint,
    total-measurements: uint,
    accurate-measurements: uint,
    authorized-by: principal,
    authorization-timestamp: uint
  }
)

;; Data Variables
(define-data-var measurement-counter uint u0)
(define-data-var incident-counter uint u0)
(define-data-var min-measurement-interval uint u6)  ;; Minimum 1 hour between measurements
(define-data-var max-response-time uint u30000)     ;; Maximum acceptable response time (30 seconds)

;; Private Functions

;; Validate service status
(define-private (is-valid-service-status (status uint))
  (or
    (is-eq status SERVICE_STATUS_OPERATIONAL)
    (is-eq status SERVICE_STATUS_DEGRADED)
    (is-eq status SERVICE_STATUS_DOWN)
    (is-eq status SERVICE_STATUS_MAINTENANCE)
  )
)

;; Validate measurement type
(define-private (is-valid-measurement-type (measurement-type uint))
  (or
    (is-eq measurement-type MEASUREMENT_TYPE_PING)
    (is-eq measurement-type MEASUREMENT_TYPE_HTTP)
    (is-eq measurement-type MEASUREMENT_TYPE_DNS)
    (is-eq measurement-type MEASUREMENT_TYPE_DATABASE)
    (is-eq measurement-type MEASUREMENT_TYPE_API)
  )
)

;; Validate SLA threshold
(define-private (is-valid-sla-threshold (threshold uint))
  (or
    (is-eq threshold SLA_THRESHOLD_99_9)
    (is-eq threshold SLA_THRESHOLD_99_5)
    (is-eq threshold SLA_THRESHOLD_99_0)
    (is-eq threshold SLA_THRESHOLD_95_0)
  )
)

;; Check if monitor is authorized
(define-private (is-authorized-monitor (monitor principal))
  (is-some (map-get? authorized-monitors { monitor: monitor }))
)

;; Calculate availability percentage
(define-private (calculate-availability-percentage (successful uint) (total uint))
  (if (is-eq total u0)
    u100
    (/ (* successful u1000) total)
  )
)

;; Check if measurement is recent enough
(define-private (is-measurement-recent (timestamp uint))
  (<= (- stacks-block-height timestamp) MAX_MEASUREMENT_AGE)
)

;; Calculate downtime duration in blocks
(define-private (calculate-downtime-duration (start-timestamp uint) (end-timestamp uint))
  (if (> end-timestamp start-timestamp)
    (- end-timestamp start-timestamp)
    u0
  )
)

;; Public Functions

;; Register new service for monitoring
(define-public (register-service
    (service-id (string-ascii 64))
    (service-name (string-ascii 200))
    (service-url (string-ascii 300))
    (service-type (string-ascii 50))
    (measurement-interval uint)
    (sla-threshold uint))
  (begin
    (asserts! (is-none (map-get? registered-services { service-id: service-id })) ERR_SERVICE_ALREADY_REGISTERED)
    (asserts! (>= measurement-interval (var-get min-measurement-interval)) ERR_INVALID_THRESHOLD)
    (asserts! (is-valid-sla-threshold sla-threshold) ERR_INVALID_THRESHOLD)
    
    (ok (map-set registered-services
      { service-id: service-id }
      {
        service-name: service-name,
        service-url: service-url,
        service-type: service-type,
        measurement-interval: measurement-interval,
        sla-threshold: sla-threshold,
        registered-by: tx-sender,
        registration-timestamp: stacks-block-height,
        is-active: true,
        last-measurement: none
      }
    ))
  )
)

;; Authorize monitoring entity
(define-public (authorize-monitor
    (monitor principal)
    (monitor-name (string-ascii 100))
    (monitor-location (string-ascii 100)))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (is-none (map-get? authorized-monitors { monitor: monitor })) ERR_SERVICE_ALREADY_REGISTERED)
    
    (ok (map-set authorized-monitors
      { monitor: monitor }
      {
        monitor-name: monitor-name,
        monitor-location: monitor-location,
        reputation-score: u100,
        total-measurements: u0,
        accurate-measurements: u0,
        authorized-by: tx-sender,
        authorization-timestamp: stacks-block-height
      }
    ))
  )
)

;; Submit availability measurement
(define-public (submit-measurement
    (service-id (string-ascii 64))
    (status uint)
    (response-time uint)
    (measurement-type uint)
    (metadata (string-ascii 300)))
  (let
    (
      (measurement-id (+ (var-get measurement-counter) u1))
      (service (unwrap! (map-get? registered-services { service-id: service-id }) ERR_NOT_FOUND))
      (monitor-info (unwrap! (map-get? authorized-monitors { monitor: tx-sender }) ERR_UNAUTHORIZED))
    )
    (asserts! (is-authorized-monitor tx-sender) ERR_UNAUTHORIZED)
    (asserts! (get is-active service) ERR_INVALID_SERVICE_ID)
    (asserts! (is-valid-service-status status) ERR_INVALID_MEASUREMENT)
    (asserts! (is-valid-measurement-type measurement-type) ERR_INVALID_MEASUREMENT)
    (asserts! (<= response-time (var-get max-response-time)) ERR_INVALID_MEASUREMENT)
    
    (var-set measurement-counter measurement-id)
    
    ;; Record measurement
    (map-set availability-measurements
      { measurement-id: measurement-id }
      {
        service-id: service-id,
        timestamp: stacks-block-height,
        status: status,
        response-time: response-time,
        measurement-type: measurement-type,
        measured-by: tx-sender,
        metadata: metadata
      }
    )
    
    ;; Update service last measurement timestamp
    (map-set registered-services
      { service-id: service-id }
      (merge service { last-measurement: (some stacks-block-height) })
    )
    
    ;; Update monitor statistics
    (map-set authorized-monitors
      { monitor: tx-sender }
      (merge monitor-info {
        total-measurements: (+ (get total-measurements monitor-info) u1)
      })
    )
    
    (ok measurement-id)
  )
)

;; Report downtime incident
(define-public (report-downtime-incident
    (service-id (string-ascii 64))
    (severity uint)
    (root-cause (string-ascii 200)))
  (let
    (
      (incident-id (+ (var-get incident-counter) u1))
      (service (unwrap! (map-get? registered-services { service-id: service-id }) ERR_NOT_FOUND))
    )
    (asserts! (is-authorized-monitor tx-sender) ERR_UNAUTHORIZED)
    (asserts! (get is-active service) ERR_INVALID_SERVICE_ID)
    (asserts! (and (>= severity u1) (<= severity u4)) ERR_INVALID_MEASUREMENT)
    
    (var-set incident-counter incident-id)
    
    (ok (map-set downtime-incidents
      { incident-id: incident-id }
      {
        service-id: service-id,
        start-timestamp: stacks-block-height,
        end-timestamp: none,
        duration-blocks: u0,
        severity: severity,
        root-cause: root-cause,
        reported-by: tx-sender,
        status: u1  ;; ongoing
      }
    ))
  )
)

;; Resolve downtime incident
(define-public (resolve-downtime-incident (incident-id uint))
  (let
    (
      (incident (unwrap! (map-get? downtime-incidents { incident-id: incident-id }) ERR_NOT_FOUND))
      (duration (calculate-downtime-duration (get start-timestamp incident) stacks-block-height))
    )
    (asserts! (is-authorized-monitor tx-sender) ERR_UNAUTHORIZED)
    (asserts! (is-eq (get status incident) u1) ERR_INVALID_MEASUREMENT)  ;; Must be ongoing
    
    (ok (map-set downtime-incidents
      { incident-id: incident-id }
      (merge incident {
        end-timestamp: (some stacks-block-height),
        duration-blocks: duration,
        status: u2  ;; resolved
      })
    ))
  )
)

;; Update SLA compliance metrics
(define-public (update-sla-compliance
    (service-id (string-ascii 64))
    (period-start uint)
    (total-measurements uint)
    (successful-measurements uint)
    (total-downtime-blocks uint))
  (let
    (
      (service (unwrap! (map-get? registered-services { service-id: service-id }) ERR_NOT_FOUND))
      (availability-pct (calculate-availability-percentage successful-measurements total-measurements))
      (sla-breached (< availability-pct (get sla-threshold service)))
    )
    (asserts! (is-authorized-monitor tx-sender) ERR_UNAUTHORIZED)
    (asserts! (get is-active service) ERR_INVALID_SERVICE_ID)
    (asserts! (>= total-measurements successful-measurements) ERR_INVALID_MEASUREMENT)
    
    (ok (map-set sla-compliance
      { service-id: service-id, period-start: period-start }
      {
        total-measurements: total-measurements,
        successful-measurements: successful-measurements,
        total-downtime-blocks: total-downtime-blocks,
        availability-percentage: availability-pct,
        sla-breached: sla-breached,
        last-updated: stacks-block-height
      }
    ))
  )
)

;; Read-only Functions

;; Get service information
(define-read-only (get-service (service-id (string-ascii 64)))
  (map-get? registered-services { service-id: service-id })
)

;; Get measurement details
(define-read-only (get-measurement (measurement-id uint))
  (map-get? availability-measurements { measurement-id: measurement-id })
)

;; Get downtime incident
(define-read-only (get-downtime-incident (incident-id uint))
  (map-get? downtime-incidents { incident-id: incident-id })
)

;; Get SLA compliance data
(define-read-only (get-sla-compliance (service-id (string-ascii 64)) (period-start uint))
  (map-get? sla-compliance { service-id: service-id, period-start: period-start })
)

;; Get monitor information
(define-read-only (get-monitor-info (monitor principal))
  (map-get? authorized-monitors { monitor: monitor })
)

;; Get measurement counter
(define-read-only (get-measurement-counter)
  (var-get measurement-counter)
)

;; Get incident counter
(define-read-only (get-incident-counter)
  (var-get incident-counter)
)

;; Check if service meets SLA
(define-read-only (check-sla-compliance (service-id (string-ascii 64)) (period-start uint))
  (match (map-get? sla-compliance { service-id: service-id, period-start: period-start })
    compliance (not (get sla-breached compliance))
    true  ;; Default to compliant if no data
  )
)

;; Calculate service uptime percentage
(define-read-only (calculate-service-uptime (service-id (string-ascii 64)) (period-start uint))
  (match (map-get? sla-compliance { service-id: service-id, period-start: period-start })
    compliance (get availability-percentage compliance)
    u1000  ;; Return 100% if no data available
  )
)
