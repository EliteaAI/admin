# admin

## Project membership notifications (EL-7340)

Before deploying this change, deploy a version of `auth_core` that supports both
lifecycle `audit_ctx` and committed removal results (`return_removed=True`; see
[auth_core #41](https://github.com/EliteaAI/auth_core/pull/41)). Manual removal
requests those results even when removal notifications are disabled.