use colored::Colorize;

use crate::models::SslAnalysisResult;

const SSLGUARD_URL: &str = "https://sslguard.net";
const CERTRADAR_URL: &str = "https://certradar.net";

/// Context for generating promotional messages
pub struct PromoContext {
    pub cert_days_remaining: Option<i64>,
    pub security_grade: Option<String>,
    pub domain_count: Option<usize>,
    pub has_issues: bool,
}

impl PromoContext {
    pub fn from_ssl_result(result: &SslAnalysisResult) -> Self {
        Self {
            cert_days_remaining: Some(result.certificate.days_remaining),
            security_grade: Some(result.security_grade.clone()),
            domain_count: None,
            has_issues: !result.issues.is_empty(),
        }
    }

    pub fn for_multi_domain(domain_count: usize) -> Self {
        Self {
            cert_days_remaining: None,
            security_grade: None,
            domain_count: Some(domain_count),
            has_issues: false,
        }
    }
}

/// Generate contextual promotional message based on analysis results
pub fn get_promo_message(ctx: &PromoContext) -> Option<String> {
    let mut messages = Vec::new();

    // Certificate expiry alerts
    if let Some(days) = ctx.cert_days_remaining {
        if days <= 30 && days > 0 {
            messages.push(format!(
                "{} Set up expiry alerts at {}",
                "🔔".to_string(),
                SSLGUARD_URL.cyan()
            ));
        } else if days <= 90 && days > 30 {
            messages.push(format!(
                "{} Monitor certificate expiry at {}",
                "💡".to_string(),
                SSLGUARD_URL.cyan()
            ));
        }
    }

    // Grade improvement suggestions
    if let Some(grade) = &ctx.security_grade {
        if !grade.starts_with('A') {
            messages.push(format!(
                "{} Track security improvements at {}",
                "📈".to_string(),
                CERTRADAR_URL.cyan()
            ));
        }
    }

    // Multi-domain management
    if let Some(count) = ctx.domain_count {
        if count >= 5 {
            messages.push(format!(
                "{} Managing {}+ domains? SSLGuard offers bulk monitoring → {}",
                "🏢".to_string(),
                count,
                SSLGUARD_URL.cyan()
            ));
        } else if count >= 2 {
            messages.push(format!(
                "{} Full web dashboard at {}",
                "📊".to_string(),
                CERTRADAR_URL.cyan()
            ));
        }
    }

    // General CTA if no specific trigger but has issues
    if messages.is_empty() && ctx.has_issues {
        messages.push(format!(
            "{} Monitor and fix issues at {}",
            "💡".to_string(),
            CERTRADAR_URL.cyan()
        ));
    }

    // Return at most one message to keep it subtle
    if messages.is_empty() {
        None
    } else {
        Some(format!("\n{}\n", messages[0]))
    }
}

/// Format promotional footer for SSL analysis
pub fn format_ssl_promo(result: &SslAnalysisResult) -> String {
    let ctx = PromoContext::from_ssl_result(result);
    get_promo_message(&ctx).unwrap_or_default()
}

/// Format promotional footer for multi-domain reports
pub fn format_multi_domain_promo(domain_count: usize) -> String {
    let ctx = PromoContext::for_multi_domain(domain_count);
    get_promo_message(&ctx).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_promo_expiring_soon() {
        let ctx = PromoContext {
            cert_days_remaining: Some(15),
            security_grade: Some("A".to_string()),
            domain_count: None,
            has_issues: false,
        };
        let msg = get_promo_message(&ctx);
        assert!(msg.is_some());
        assert!(msg.unwrap().contains("expiry alerts"));
    }

    #[test]
    fn test_promo_low_grade() {
        let ctx = PromoContext {
            cert_days_remaining: Some(365),
            security_grade: Some("B".to_string()),
            domain_count: None,
            has_issues: false,
        };
        let msg = get_promo_message(&ctx);
        assert!(msg.is_some());
        assert!(msg.unwrap().contains("improvements"));
    }

    #[test]
    fn test_promo_multi_domain() {
        let ctx = PromoContext::for_multi_domain(10);
        let msg = get_promo_message(&ctx);
        assert!(msg.is_some());
        assert!(msg.unwrap().contains("bulk monitoring"));
    }

    #[test]
    fn test_promo_no_message_for_good_cert() {
        let ctx = PromoContext {
            cert_days_remaining: Some(365),
            security_grade: Some("A+".to_string()),
            domain_count: None,
            has_issues: false,
        };
        let msg = get_promo_message(&ctx);
        assert!(msg.is_none());
    }
}
