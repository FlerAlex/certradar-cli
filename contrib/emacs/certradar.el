;;; certradar.el --- Check SSL/TLS certificates from Emacs -*- lexical-binding: t; -*-

;; Author: Alex Fler
;; URL: https://github.com/FlerAlex/certradar-cli
;; Version: 0.2.0
;; Keywords: tools, networking, ssl, tls, certificates
;; Package-Requires: ((emacs "25.1"))

;;; Commentary:

;; A lightweight Emacs wrapper around certradar-cli for checking SSL/TLS
;; certificates without leaving your editor.
;;
;; Features:
;;   - M-x check-ssl            → prompt for a domain and view its cert report
;;   - M-x check-ssl-async      → same thing, non-blocking
;;   - M-x check-ssl-at-point   → check whatever domain is under your cursor
;;   - M-x check-ssl-batch      → check multiple domains at once
;;   - Expiry watcher            → background timer warns you about expiring certs
;;
;; Install certradar-cli first:
;;   cargo install certradar-cli
;;
;; Quickstart:
;;   (require 'certradar)
;;   (global-set-key (kbd "C-c s") #'check-ssl-at-point)
;;
;; For org-babel usage, see the README or the blog post at theopsmechanic.com.

;;; Code:

;;;; -------------------------------------------------------------------
;;;; Utilities
;;;; -------------------------------------------------------------------

(defun check-ssl--clean-domain (domain)
  "Strip protocol prefix and port suffix from DOMAIN."
  (let ((cleaned (replace-regexp-in-string "https?://" "" domain)))
    (replace-regexp-in-string ":[0-9]+$" "" cleaned)))

;;;; -------------------------------------------------------------------
;;;; Core: Interactive SSL check (synchronous)
;;;; -------------------------------------------------------------------

(defun check-ssl (domain)
  "Check SSL/TLS certificate for DOMAIN using certradar-cli.
Results are displayed in a dedicated read-only buffer.
Note: this is blocking.  Use `check-ssl-async' if you need
to keep working while the check runs."
  (interactive "sDomain: ")
  (let* ((clean-domain (check-ssl--clean-domain domain))
         (buf-name (format "*SSL: %s*" clean-domain))
         (buf (get-buffer-create buf-name)))
    (with-current-buffer buf
      (read-only-mode -1)
      (erase-buffer)
      (insert (format "SSL Certificate Report: %s\n" clean-domain))
      (insert (make-string 50 ?─))
      (insert "\n\n")
      (let ((result (shell-command-to-string
                     (format "certradar-cli ssl --no-color %s 2>&1"
                             (shell-quote-argument clean-domain)))))
        (insert result))
      (goto-char (point-min))
      (special-mode))
    (switch-to-buffer-other-window buf)))

;;;; -------------------------------------------------------------------
;;;; Core: Async SSL check (non-blocking)
;;;; -------------------------------------------------------------------

(defun check-ssl-async (domain)
  "Check SSL/TLS certificate for DOMAIN asynchronously.
Unlike `check-ssl', this won't freeze Emacs if DNS is slow
or the domain is hanging."
  (interactive "sDomain: ")
  (let* ((clean-domain (check-ssl--clean-domain domain))
         (buf-name (format "*SSL: %s*" clean-domain))
         (buf (get-buffer-create buf-name)))
    (with-current-buffer buf
      (read-only-mode -1)
      (erase-buffer)
      (insert (format "SSL Certificate Report: %s\n" clean-domain))
      (insert (make-string 50 ?─))
      (insert "\n\nFetching...\n"))
    (switch-to-buffer-other-window buf)
    (make-process
     :name (format "certradar-%s" clean-domain)
     :buffer buf
     :command (list "certradar-cli" "ssl" "--no-color" clean-domain)
     :sentinel (lambda (proc _event)
                 (when (eq (process-status proc) 'exit)
                   (with-current-buffer (process-buffer proc)
                     (goto-char (point-min))
                     (when (search-forward "Fetching..." nil t)
                       (replace-match ""))
                     (special-mode)))))))

;;;; -------------------------------------------------------------------
;;;; Check domain at point
;;;; -------------------------------------------------------------------

(defun check-ssl-at-point ()
  "Check SSL cert for the domain under point.
Tries to grab a URL first, then falls back to the symbol at point
if it looks like a domain (contains a dot).  Prompts otherwise."
  (interactive)
  (let ((domain (thing-at-point 'url t)))
    (if domain
        (check-ssl domain)
      (let ((word (thing-at-point 'symbol t)))
        (if (and word (string-match-p "\\." word))
            (check-ssl word)
          (call-interactively #'check-ssl))))))

(defun check-ssl-at-point-async ()
  "Like `check-ssl-at-point' but non-blocking."
  (interactive)
  (let ((domain (thing-at-point 'url t)))
    (if domain
        (check-ssl-async domain)
      (let ((word (thing-at-point 'symbol t)))
        (if (and word (string-match-p "\\." word))
            (check-ssl-async word)
          (call-interactively #'check-ssl-async))))))

;;;; -------------------------------------------------------------------
;;;; Batch check
;;;; -------------------------------------------------------------------

(defun check-ssl-batch (domains)
  "Check SSL certs for a list of DOMAINS.
Results are displayed in a single buffer."
  (interactive
   (list (split-string (read-string "Domains (space-separated): "))))
  (let* ((buf-name "*SSL: Batch Report*")
         (buf (get-buffer-create buf-name)))
    (with-current-buffer buf
      (read-only-mode -1)
      (erase-buffer)
      (insert "SSL Batch Certificate Report\n")
      (insert (make-string 50 ?─))
      (insert "\n\n")
      (dolist (domain domains)
        (let ((clean (check-ssl--clean-domain domain)))
          (insert (format "━━━ %s ━━━\n" clean))
          (insert (shell-command-to-string
                   (format "certradar-cli ssl --no-color %s 2>&1"
                           (shell-quote-argument clean))))
          (insert "\n\n")))
      (goto-char (point-min))
      (special-mode))
    (switch-to-buffer-other-window buf)))

;;;; -------------------------------------------------------------------
;;;; Expiry watcher
;;;; -------------------------------------------------------------------

(defvar ssl-watch-domains '()
  "List of domains to monitor for certificate expiry.
Example: (setq ssl-watch-domains \\='(\"example.com\" \"api.example.com\"))")

(defvar ssl-expiry-warning-days 14
  "Warn when a certificate expires within this many days.")

(defvar ssl--expiry-timer nil
  "Internal timer for periodic expiry checks.")

(defun ssl-check-expiry-warnings ()
  "Check `ssl-watch-domains' and warn about upcoming expirations."
  (interactive)
  (when ssl-watch-domains
    (dolist (domain ssl-watch-domains)
      (let ((output (shell-command-to-string
                     (format "certradar-cli ssl --no-color %s --json 2>/dev/null"
                             (shell-quote-argument domain)))))
        (when (string-match "\"days_until_expiry\":\\s*\\([0-9]+\\)" output)
          (let ((days (string-to-number (match-string 1 output))))
            (when (<= days ssl-expiry-warning-days)
              (message "SSL WARNING: %s expires in %d days!" domain days)
              (run-with-timer 0.5 nil
                (lambda (d n)
                  (display-warning 'ssl
                    (format "%s certificate expires in %d days" d n)
                    :warning))
                domain days))))))))

(defun ssl-watch-start (&optional interval)
  "Start the SSL expiry watcher.
Checks immediately, then every INTERVAL seconds (default 21600 = 6 hours)."
  (interactive)
  (ssl-watch-stop)
  (let ((secs (or interval 21600)))
    (ssl-check-expiry-warnings)
    (setq ssl--expiry-timer
          (run-with-timer secs secs #'ssl-check-expiry-warnings))
    (message "SSL watcher started (interval: %ds, watching: %s)"
             secs (string-join ssl-watch-domains ", "))))

(defun ssl-watch-stop ()
  "Stop the SSL expiry watcher."
  (interactive)
  (when ssl--expiry-timer
    (cancel-timer ssl--expiry-timer)
    (setq ssl--expiry-timer nil)
    (message "SSL watcher stopped.")))

;;;; -------------------------------------------------------------------
;;;; Optional keybindings
;;;; -------------------------------------------------------------------

;; Uncomment to enable globally:
;; (global-set-key (kbd "C-c s") #'check-ssl-at-point)
;; (global-set-key (kbd "C-c S") #'check-ssl-batch)
;;
;; For async versions:
;; (global-set-key (kbd "C-c s") #'check-ssl-at-point-async)

(provide 'certradar)

;;; certradar.el ends here
