//! Marketplace SaaS Web Portal Backend
//!
//! API for the hosted marketplace portal where users discover, rate, and install transforms.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The main marketplace portal managing transforms, users, and statistics.
pub struct MarketplacePortal {
    transforms: Arc<RwLock<HashMap<String, MarketplaceEntry>>>,
    users: Arc<RwLock<HashMap<String, PortalUser>>>,
    config: PortalConfig,
    stats: Arc<PortalStats>,
}

/// Configuration for the marketplace portal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalConfig {
    pub max_transforms: usize,
    pub max_reviews_per_user: usize,
    pub featured_count: usize,
    pub require_security_audit: bool,
}

/// A published transform entry in the marketplace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceEntry {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub long_description: Option<String>,
    pub author: PublisherInfo,
    pub category: String,
    pub tags: Vec<String>,
    pub downloads: u64,
    pub rating: f64,
    pub review_count: u32,
    pub reviews: Vec<Review>,
    pub pricing: Pricing,
    pub wasm_url: String,
    pub checksum: String,
    pub screenshots: Vec<String>,
    pub readme: Option<String>,
    pub changelog: Option<String>,
    pub published_at: String,
    pub updated_at: String,
    pub featured: bool,
    pub verified: bool,
}

/// Information about the publisher of a transform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublisherInfo {
    pub name: String,
    pub email: String,
    pub org: Option<String>,
    pub verified: bool,
}

/// A user review of a marketplace transform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub user: String,
    pub rating: u8,
    pub comment: String,
    pub created_at: String,
}

/// Pricing model for a transform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Pricing {
    Free,
    OneTime { price_cents: u64 },
    Subscription { monthly_cents: u64 },
}

/// A registered portal user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalUser {
    pub id: String,
    pub username: String,
    pub email: String,
    pub published_count: u32,
    pub installed: Vec<String>,
    pub created_at: String,
}

/// Atomic counters for portal-wide statistics.
pub struct PortalStats {
    pub total_transforms: AtomicU64,
    pub total_users: AtomicU64,
    pub total_downloads: AtomicU64,
    pub total_reviews: AtomicU64,
}

/// Sort options for listing transforms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortOption {
    Popular,
    Recent,
    TopRated,
    MostDownloaded,
}

/// A snapshot of portal statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalStatsSnapshot {
    pub total_transforms: u64,
    pub total_users: u64,
    pub total_downloads: u64,
    pub total_reviews: u64,
}

// ---------------------------------------------------------------------------
// Default implementations
// ---------------------------------------------------------------------------

impl Default for PortalConfig {
    fn default() -> Self {
        Self {
            max_transforms: 10_000,
            max_reviews_per_user: 50,
            featured_count: 10,
            require_security_audit: false,
        }
    }
}

impl Default for PortalStats {
    fn default() -> Self {
        Self {
            total_transforms: AtomicU64::new(0),
            total_users: AtomicU64::new(0),
            total_downloads: AtomicU64::new(0),
            total_reviews: AtomicU64::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl MarketplacePortal {
    /// Create a new marketplace portal with the given configuration.
    pub fn new(config: PortalConfig) -> Self {
        info!(
            max_transforms = config.max_transforms,
            featured_count = config.featured_count,
            "Initializing marketplace portal"
        );
        Self {
            transforms: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(PortalStats::default()),
        }
    }

    /// Publish a new transform to the marketplace.
    pub async fn publish_transform(&self, mut entry: MarketplaceEntry) -> Result<String, String> {
        let transforms = self.transforms.read().await;
        if transforms.len() >= self.config.max_transforms {
            warn!(
                max = self.config.max_transforms,
                "Transform capacity reached"
            );
            return Err("marketplace is at capacity".into());
        }
        drop(transforms);

        if entry.id.is_empty() {
            entry.id = Uuid::new_v4().to_string();
        }
        let now = chrono_now();
        if entry.published_at.is_empty() {
            entry.published_at = now.clone();
        }
        entry.updated_at = now;

        let id = entry.id.clone();
        info!(id = %id, name = %entry.name, "Publishing transform");
        self.transforms.write().await.insert(id.clone(), entry);
        self.stats.total_transforms.fetch_add(1, Ordering::Relaxed);
        Ok(id)
    }

    /// Get a transform by its id.
    pub async fn get_transform(&self, id: &str) -> Option<MarketplaceEntry> {
        self.transforms.read().await.get(id).cloned()
    }

    /// List transforms with optional category filter, sorting, and pagination.
    pub async fn list_transforms(
        &self,
        category: Option<&str>,
        sort: SortOption,
        page: usize,
        limit: usize,
    ) -> Vec<MarketplaceEntry> {
        let transforms = self.transforms.read().await;
        let mut entries: Vec<MarketplaceEntry> = transforms
            .values()
            .filter(|e| category.map_or(true, |c| e.category == c))
            .cloned()
            .collect();

        match sort {
            SortOption::Popular => entries.sort_by(|a, b| b.downloads.cmp(&a.downloads)),
            SortOption::Recent => entries.sort_by(|a, b| b.published_at.cmp(&a.published_at)),
            SortOption::TopRated => {
                entries.sort_by(|a, b| b.rating.partial_cmp(&a.rating).unwrap_or(std::cmp::Ordering::Equal))
            }
            SortOption::MostDownloaded => entries.sort_by(|a, b| b.downloads.cmp(&a.downloads)),
        }

        let start = page * limit;
        entries.into_iter().skip(start).take(limit).collect()
    }

    /// Search transforms by name, description, or tags.
    pub async fn search(&self, query: &str) -> Vec<MarketplaceEntry> {
        let q = query.to_lowercase();
        let transforms = self.transforms.read().await;
        transforms
            .values()
            .filter(|e| {
                e.name.to_lowercase().contains(&q)
                    || e.description.to_lowercase().contains(&q)
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .cloned()
            .collect()
    }

    /// Add a review to a transform.
    pub async fn add_review(&self, transform_id: &str, review: Review) -> Result<(), String> {
        if review.rating > 5 {
            return Err("rating must be between 0 and 5".into());
        }

        let mut transforms = self.transforms.write().await;
        let entry = transforms
            .get_mut(transform_id)
            .ok_or_else(|| "transform not found".to_string())?;

        // Enforce per-user review limit
        let user_review_count = entry.reviews.iter().filter(|r| r.user == review.user).count();
        if user_review_count >= self.config.max_reviews_per_user {
            return Err("review limit reached for this user".into());
        }

        entry.reviews.push(review);
        entry.review_count = entry.reviews.len() as u32;

        // Recalculate average rating
        let total: f64 = entry.reviews.iter().map(|r| r.rating as f64).sum();
        entry.rating = total / entry.reviews.len() as f64;

        debug!(
            transform_id = %transform_id,
            new_rating = entry.rating,
            "Review added"
        );
        self.stats.total_reviews.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Get the list of featured transforms.
    pub async fn get_featured(&self) -> Vec<MarketplaceEntry> {
        let transforms = self.transforms.read().await;
        let mut featured: Vec<MarketplaceEntry> =
            transforms.values().filter(|e| e.featured).cloned().collect();
        featured.sort_by(|a, b| b.downloads.cmp(&a.downloads));
        featured.truncate(self.config.featured_count);
        featured
    }

    /// Get the most popular transforms by download count.
    pub async fn get_popular(&self, limit: usize) -> Vec<MarketplaceEntry> {
        let transforms = self.transforms.read().await;
        let mut entries: Vec<MarketplaceEntry> = transforms.values().cloned().collect();
        entries.sort_by(|a, b| b.downloads.cmp(&a.downloads));
        entries.truncate(limit);
        entries
    }

    /// Register a new portal user.
    pub async fn register_user(&self, mut user: PortalUser) -> Result<String, String> {
        if user.id.is_empty() {
            user.id = Uuid::new_v4().to_string();
        }
        if user.created_at.is_empty() {
            user.created_at = chrono_now();
        }

        let mut users = self.users.write().await;
        if users.values().any(|u| u.username == user.username) {
            return Err("username already taken".into());
        }

        let id = user.id.clone();
        info!(id = %id, username = %user.username, "User registered");
        users.insert(id.clone(), user);
        self.stats.total_users.fetch_add(1, Ordering::Relaxed);
        Ok(id)
    }

    /// Record a download for a transform and track it on the user.
    pub async fn record_download(&self, transform_id: &str, user_id: Option<&str>) -> Result<(), String> {
        {
            let mut transforms = self.transforms.write().await;
            let entry = transforms
                .get_mut(transform_id)
                .ok_or_else(|| "transform not found".to_string())?;
            entry.downloads += 1;
        }

        if let Some(uid) = user_id {
            let mut users = self.users.write().await;
            if let Some(user) = users.get_mut(uid) {
                if !user.installed.contains(&transform_id.to_string()) {
                    user.installed.push(transform_id.to_string());
                }
            }
        }

        self.stats.total_downloads.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Return a snapshot of the portal statistics.
    pub fn stats(&self) -> PortalStatsSnapshot {
        PortalStatsSnapshot {
            total_transforms: self.stats.total_transforms.load(Ordering::Relaxed),
            total_users: self.stats.total_users.load(Ordering::Relaxed),
            total_downloads: self.stats.total_downloads.load(Ordering::Relaxed),
            total_reviews: self.stats.total_reviews.load(Ordering::Relaxed),
        }
    }
}

/// Simple ISO-8601-ish timestamp without pulling in chrono.
fn chrono_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", d.as_secs())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_publisher() -> PublisherInfo {
        PublisherInfo {
            name: "alice".into(),
            email: "alice@example.com".into(),
            org: None,
            verified: true,
        }
    }

    fn sample_entry(name: &str) -> MarketplaceEntry {
        MarketplaceEntry {
            id: String::new(),
            name: name.into(),
            version: "1.0.0".into(),
            description: format!("{name} transform"),
            long_description: None,
            author: default_publisher(),
            category: "analytics".into(),
            tags: vec!["data".into()],
            downloads: 0,
            rating: 0.0,
            review_count: 0,
            reviews: vec![],
            pricing: Pricing::Free,
            wasm_url: "https://cdn.example.com/t.wasm".into(),
            checksum: "abc123".into(),
            screenshots: vec![],
            readme: None,
            changelog: None,
            published_at: String::new(),
            updated_at: String::new(),
            featured: false,
            verified: false,
        }
    }

    fn sample_user(username: &str) -> PortalUser {
        PortalUser {
            id: String::new(),
            username: username.into(),
            email: format!("{username}@example.com"),
            published_count: 0,
            installed: vec![],
            created_at: String::new(),
        }
    }

    #[tokio::test]
    async fn test_new_portal() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        let s = portal.stats();
        assert_eq!(s.total_transforms, 0);
        assert_eq!(s.total_users, 0);
    }

    #[tokio::test]
    async fn test_publish_transform() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        let id = portal.publish_transform(sample_entry("filter")).await.unwrap();
        assert!(!id.is_empty());
        assert_eq!(portal.stats().total_transforms, 1);
    }

    #[tokio::test]
    async fn test_publish_at_capacity() {
        let cfg = PortalConfig { max_transforms: 1, ..Default::default() };
        let portal = MarketplacePortal::new(cfg);
        portal.publish_transform(sample_entry("a")).await.unwrap();
        let res = portal.publish_transform(sample_entry("b")).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_get_transform() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        let id = portal.publish_transform(sample_entry("x")).await.unwrap();
        let entry = portal.get_transform(&id).await.unwrap();
        assert_eq!(entry.name, "x");
    }

    #[tokio::test]
    async fn test_get_transform_not_found() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        assert!(portal.get_transform("missing").await.is_none());
    }

    #[tokio::test]
    async fn test_list_transforms_by_category() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        let mut e = sample_entry("a");
        e.category = "etl".into();
        portal.publish_transform(e).await.unwrap();
        portal.publish_transform(sample_entry("b")).await.unwrap();

        let results = portal.list_transforms(Some("etl"), SortOption::Recent, 0, 10).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].category, "etl");
    }

    #[tokio::test]
    async fn test_list_transforms_pagination() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        for i in 0..5 {
            portal.publish_transform(sample_entry(&format!("t{i}"))).await.unwrap();
        }
        let page = portal.list_transforms(None, SortOption::Recent, 1, 2).await;
        assert_eq!(page.len(), 2);
    }

    #[tokio::test]
    async fn test_list_transforms_sort_popular() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        let mut a = sample_entry("low");
        a.downloads = 1;
        let mut b = sample_entry("high");
        b.downloads = 100;
        portal.publish_transform(a).await.unwrap();
        portal.publish_transform(b).await.unwrap();

        let results = portal.list_transforms(None, SortOption::Popular, 0, 10).await;
        assert_eq!(results[0].name, "high");
    }

    #[tokio::test]
    async fn test_search_by_name() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        portal.publish_transform(sample_entry("json-filter")).await.unwrap();
        portal.publish_transform(sample_entry("csv-parser")).await.unwrap();

        let results = portal.search("json").await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "json-filter");
    }

    #[tokio::test]
    async fn test_search_by_tag() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        let mut e = sample_entry("x");
        e.tags = vec!["special".into()];
        portal.publish_transform(e).await.unwrap();

        let results = portal.search("special").await;
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_add_review() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        let id = portal.publish_transform(sample_entry("t")).await.unwrap();
        let review = Review { user: "bob".into(), rating: 4, comment: "great".into(), created_at: String::new() };
        portal.add_review(&id, review).await.unwrap();

        let entry = portal.get_transform(&id).await.unwrap();
        assert_eq!(entry.review_count, 1);
        assert!((entry.rating - 4.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_add_review_invalid_rating() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        let id = portal.publish_transform(sample_entry("t")).await.unwrap();
        let review = Review { user: "u".into(), rating: 6, comment: "".into(), created_at: String::new() };
        assert!(portal.add_review(&id, review).await.is_err());
    }

    #[tokio::test]
    async fn test_add_review_transform_not_found() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        let review = Review { user: "u".into(), rating: 3, comment: "ok".into(), created_at: String::new() };
        assert!(portal.add_review("nope", review).await.is_err());
    }

    #[tokio::test]
    async fn test_get_featured() {
        let portal = MarketplacePortal::new(PortalConfig { featured_count: 1, ..Default::default() });
        let mut e1 = sample_entry("a");
        e1.featured = true;
        e1.downloads = 10;
        let mut e2 = sample_entry("b");
        e2.featured = true;
        e2.downloads = 20;
        portal.publish_transform(e1).await.unwrap();
        portal.publish_transform(e2).await.unwrap();

        let featured = portal.get_featured().await;
        assert_eq!(featured.len(), 1);
        assert_eq!(featured[0].name, "b");
    }

    #[tokio::test]
    async fn test_get_popular() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        let mut e = sample_entry("pop");
        e.downloads = 999;
        portal.publish_transform(e).await.unwrap();
        portal.publish_transform(sample_entry("x")).await.unwrap();

        let popular = portal.get_popular(1).await;
        assert_eq!(popular.len(), 1);
        assert_eq!(popular[0].name, "pop");
    }

    #[tokio::test]
    async fn test_register_user() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        let id = portal.register_user(sample_user("alice")).await.unwrap();
        assert!(!id.is_empty());
        assert_eq!(portal.stats().total_users, 1);
    }

    #[tokio::test]
    async fn test_register_duplicate_username() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        portal.register_user(sample_user("alice")).await.unwrap();
        assert!(portal.register_user(sample_user("alice")).await.is_err());
    }

    #[tokio::test]
    async fn test_record_download() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        let tid = portal.publish_transform(sample_entry("t")).await.unwrap();
        let uid = portal.register_user(sample_user("bob")).await.unwrap();

        portal.record_download(&tid, Some(&uid)).await.unwrap();
        let entry = portal.get_transform(&tid).await.unwrap();
        assert_eq!(entry.downloads, 1);
        assert_eq!(portal.stats().total_downloads, 1);
    }

    #[tokio::test]
    async fn test_record_download_not_found() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        assert!(portal.record_download("nope", None).await.is_err());
    }

    #[tokio::test]
    async fn test_stats_snapshot() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        portal.publish_transform(sample_entry("a")).await.unwrap();
        portal.register_user(sample_user("u")).await.unwrap();
        let s = portal.stats();
        assert_eq!(s.total_transforms, 1);
        assert_eq!(s.total_users, 1);
    }

    #[tokio::test]
    async fn test_review_recalculates_average() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        let id = portal.publish_transform(sample_entry("t")).await.unwrap();
        let r1 = Review { user: "a".into(), rating: 2, comment: "".into(), created_at: String::new() };
        let r2 = Review { user: "b".into(), rating: 4, comment: "".into(), created_at: String::new() };
        portal.add_review(&id, r1).await.unwrap();
        portal.add_review(&id, r2).await.unwrap();

        let entry = portal.get_transform(&id).await.unwrap();
        assert!((entry.rating - 3.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_download_no_user() {
        let portal = MarketplacePortal::new(PortalConfig::default());
        let tid = portal.publish_transform(sample_entry("t")).await.unwrap();
        portal.record_download(&tid, None).await.unwrap();
        assert_eq!(portal.stats().total_downloads, 1);
    }
}
