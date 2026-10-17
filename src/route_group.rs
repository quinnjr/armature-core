//! Route groups for organizing routes with shared configuration
//!
//! Route groups allow you to organize routes with shared:
//! - Path prefixes
//! - Middleware
//! - Guards
//! - Configuration
//!
//! A group's guards and middleware are **enforced** on every route registered
//! through it ([`RouteGroup::add_route`] / [`RouteGroup::route`]): each such
//! route runs the group's middleware (outermost first), then its guards, then
//! the handler. They are bound to the route itself, not to a URL prefix, so no
//! spelling of the path reaches the handler around them.
//!
//! # Examples
//!
//! ```
//! use armature_core::{Error, HttpMethod, HttpRequest, HttpResponse, RouteGroup, Router};
//!
//! async fn list_users(_req: HttpRequest) -> Result<HttpResponse, Error> {
//!     Ok(HttpResponse::ok())
//! }
//!
//! let mut router = Router::new();
//! let api_group = RouteGroup::new().prefix("/api/v1");
//! api_group.route(&mut router, HttpMethod::GET, "/users", list_users);
//! assert_eq!(router.routes[0].path, "/api/v1/users");
//! ```

use crate::handler::IntoHandler;
use crate::{Error, Guard, GuardContext, HttpMethod, Middleware, Route, Router};
use std::sync::Arc;

/// A guard that checks all guards in a list
pub struct MultiGuard {
    guards: Vec<Box<dyn Guard>>,
}

impl MultiGuard {
    pub fn new(guards: Vec<Box<dyn Guard>>) -> Self {
        Self { guards }
    }
}

#[async_trait::async_trait]
impl Guard for MultiGuard {
    async fn can_activate(&self, context: &GuardContext) -> Result<bool, Error> {
        for guard in &self.guards {
            if !guard.can_activate(context).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Holds an ordered list of middleware.
///
/// Note: `MultiMiddleware` does not implement the `Middleware` trait and
/// therefore does not itself chain or dispatch anything. It is a simple
/// container exposing `get_middleware()` so callers can retrieve the list;
/// actual sequential middleware execution is handled elsewhere (see
/// `MiddlewareChain` in `middleware.rs`).
pub struct MultiMiddleware {
    middleware: Vec<Arc<dyn Middleware>>,
}

impl MultiMiddleware {
    pub fn new(middleware: Vec<Arc<dyn Middleware>>) -> Self {
        Self { middleware }
    }

    pub fn get_middleware(&self) -> &[Arc<dyn Middleware>] {
        &self.middleware
    }
}

/// Route group configuration
///
/// A route group allows you to organize routes with shared configuration
/// including path prefixes, middleware, and guards.
///
/// # Examples
///
/// ```
/// use armature_core::RouteGroup;
///
/// // Create an API group
/// let api = RouteGroup::new()
///     .prefix("/api/v1");
///
/// // Create a nested admin group
/// let admin = RouteGroup::new()
///     .prefix("/api/v1/admin");
/// ```
#[derive(Clone, Default)]
pub struct RouteGroup {
    /// Path prefix for all routes in this group
    prefix: String,

    /// Middleware to apply to all routes
    middleware: Vec<Arc<dyn Middleware>>,

    /// Guards to apply to all routes
    ///
    /// Stored as `Arc<dyn Guard>` so that cloned and nested groups share
    /// (rather than silently lose) their guards.
    guards: Vec<Arc<dyn Guard>>,
}

impl RouteGroup {
    /// Create a new route group
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the path prefix for this group
    ///
    /// All routes added to this group will have this prefix prepended.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use armature_core::RouteGroup;
    ///
    /// let group = RouteGroup::new().prefix("/api/v1");
    /// // Routes like "/users" will become "/api/v1/users"
    /// ```
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        let prefix = prefix.into();
        // Ensure prefix starts with / and doesn't end with /
        let prefix = if !prefix.starts_with('/') {
            format!("/{}", prefix)
        } else {
            prefix
        };
        let prefix = prefix.trim_end_matches('/').to_string();

        self.prefix = prefix;
        self
    }

    /// Add middleware to this group
    ///
    /// Runs, outermost first, for every route registered through this group,
    /// before the group's guards.
    pub fn middleware(mut self, middleware: Arc<dyn Middleware>) -> Self {
        self.middleware.push(middleware);
        self
    }

    /// Add multiple middleware to this group
    pub fn with_middleware(mut self, middleware: Vec<Arc<dyn Middleware>>) -> Self {
        self.middleware.extend(middleware);
        self
    }

    /// Add a guard to this group
    ///
    /// Checked for every route registered through this group, after the
    /// group's middleware; a guard returning `Ok(false)` answers `403`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use armature_core::{RouteGroup, AuthenticationGuard};
    ///
    /// let group = RouteGroup::new()
    ///     .guard(Box::new(AuthenticationGuard));
    /// ```
    pub fn guard(mut self, guard: Box<dyn Guard>) -> Self {
        self.guards.push(Arc::from(guard));
        self
    }

    /// Add multiple guards to this group
    ///
    /// All guards must pass for the route to be accessed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use armature_core::{RouteGroup, AuthenticationGuard, RolesGuard};
    ///
    /// let group = RouteGroup::new()
    ///     .with_guards(vec![
    ///         Box::new(AuthenticationGuard),
    ///         Box::new(RolesGuard::new(vec!["admin".to_string()])),
    ///     ]);
    /// ```
    pub fn with_guards(mut self, guards: Vec<Box<dyn Guard>>) -> Self {
        self.guards.extend(guards.into_iter().map(Arc::from));
        self
    }

    /// Register `route` through this group.
    ///
    /// The group's prefix is applied to the route's path, and the group's
    /// middleware and guards are bound to the route so they run on every
    /// request it serves, however that request spelled the path.
    pub fn add_route(&self, router: &mut Router, mut route: Route) -> &Self {
        route.path = self.apply_prefix(&route.path);
        let index = router.routes.len();
        router.add_route(route);
        router.layer_routes(index..index + 1, &self.middleware, &self.guards);
        self
    }

    /// Register `handler` for `method` at `path` (prefixed) through this group.
    ///
    /// See [`RouteGroup::add_route`].
    pub fn route<H, Args>(
        &self,
        router: &mut Router,
        method: HttpMethod,
        path: &str,
        handler: H,
    ) -> &Self
    where
        H: IntoHandler<Args>,
    {
        self.add_route(router, Route::new(method, path, handler))
    }

    /// Get the prefix for this group
    pub fn get_prefix(&self) -> &str {
        &self.prefix
    }

    /// Apply the group's prefix to a path
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use armature_core::RouteGroup;
    ///
    /// let group = RouteGroup::new().prefix("/api/v1");
    /// assert_eq!(group.apply_prefix("/users"), "/api/v1/users");
    /// ```
    pub fn apply_prefix(&self, path: &str) -> String {
        if self.prefix.is_empty() {
            path.to_string()
        } else {
            let path = path.trim_start_matches('/');
            if path.is_empty() {
                self.prefix.clone()
            } else {
                format!("{}/{}", self.prefix, path)
            }
        }
    }

    /// Get all middleware for this group
    pub fn get_middleware(&self) -> &[Arc<dyn Middleware>] {
        &self.middleware
    }

    /// Get all guards for this group
    pub fn get_guards(&self) -> &[Arc<dyn Guard>] {
        &self.guards
    }

    /// Combine this group with a parent group
    ///
    /// Creates a new group that inherits configuration from both.
    pub fn with_parent(self, parent: &RouteGroup) -> Self {
        let mut new_group = RouteGroup::new();

        // Combine prefixes
        if !parent.prefix.is_empty() {
            new_group.prefix = if !self.prefix.is_empty() {
                format!("{}{}", parent.prefix, self.prefix)
            } else {
                parent.prefix.clone()
            };
        } else {
            new_group.prefix = self.prefix;
        }

        // Combine middleware (parent first, then child)
        new_group
            .middleware
            .extend(parent.middleware.iter().cloned());
        new_group.middleware.extend(self.middleware);

        // Combine guards (parent first, then child)
        new_group.guards.extend(parent.guards.iter().cloned());
        new_group.guards.extend(self.guards);

        new_group
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestGuard;

    #[async_trait::async_trait]
    impl Guard for TestGuard {
        async fn can_activate(&self, _context: &GuardContext) -> Result<bool, Error> {
            Ok(true)
        }
    }

    #[test]
    fn test_route_group_clone_preserves_guards() {
        let group = RouteGroup::new()
            .prefix("/api")
            .guard(Box::new(TestGuard))
            .guard(Box::new(TestGuard));

        let cloned = group.clone();
        assert_eq!(cloned.get_guards().len(), 2);
        assert_eq!(group.get_guards().len(), 2);
    }

    #[test]
    fn test_route_group_with_parent_inherits_guards() {
        let parent = RouteGroup::new().prefix("/api").guard(Box::new(TestGuard));
        let child = RouteGroup::new()
            .prefix("/v1")
            .guard(Box::new(TestGuard))
            .with_parent(&parent);

        // Parent guard + child guard
        assert_eq!(child.get_guards().len(), 2);
    }

    #[test]
    fn test_route_group_prefix() {
        let group = RouteGroup::new().prefix("/api/v1");
        assert_eq!(group.get_prefix(), "/api/v1");
        assert_eq!(group.apply_prefix("/users"), "/api/v1/users");
        assert_eq!(group.apply_prefix("users"), "/api/v1/users");
        assert_eq!(group.apply_prefix("/"), "/api/v1");
        assert_eq!(group.apply_prefix(""), "/api/v1");
    }

    #[test]
    fn test_route_group_prefix_normalization() {
        let group = RouteGroup::new().prefix("api/v1/");
        assert_eq!(group.get_prefix(), "/api/v1");
    }

    #[test]
    fn test_route_group_no_prefix() {
        let group = RouteGroup::new();
        assert_eq!(group.get_prefix(), "");
        assert_eq!(group.apply_prefix("/users"), "/users");
    }

    async fn ok_handler(_req: crate::HttpRequest) -> Result<crate::HttpResponse, Error> {
        Ok(crate::HttpResponse::ok())
    }

    struct DenyGuard;

    #[async_trait::async_trait]
    impl Guard for DenyGuard {
        async fn can_activate(&self, _context: &GuardContext) -> Result<bool, Error> {
            Ok(false)
        }
    }

    /// Records the order middleware and guards run in.
    struct Recorder(Arc<std::sync::Mutex<Vec<&'static str>>>, &'static str);

    #[async_trait::async_trait]
    impl Middleware for Recorder {
        async fn handle(
            &self,
            req: crate::HttpRequest,
            next: crate::Next,
        ) -> Result<crate::HttpResponse, Error> {
            self.0.lock().unwrap().push(self.1);
            next(req).await
        }
    }

    #[async_trait::async_trait]
    impl Guard for Recorder {
        async fn can_activate(&self, _context: &GuardContext) -> Result<bool, Error> {
            self.0.lock().unwrap().push(self.1);
            Ok(true)
        }
    }

    /// The regression: a group guard used to be recorded and never run.
    #[tokio::test]
    async fn a_group_guard_is_enforced_on_every_spelling_of_the_path() {
        let mut router = Router::new();
        RouteGroup::new()
            .prefix("/admin")
            .guard(Box::new(DenyGuard))
            .route(&mut router, HttpMethod::GET, "/users", ok_handler);
        let optimized = crate::route_cache::OptimizedRouter::from_router(&router);

        for path in ["/admin/users", "//admin/users", "/admin//users/"] {
            let linear = router
                .route(crate::HttpRequest::new("GET", path))
                .await
                .unwrap();
            assert_eq!(linear.status, 403, "{path} via Router");
            let fast = optimized
                .route(crate::HttpRequest::new("GET", path))
                .await
                .unwrap();
            assert_eq!(fast.status, 403, "{path} via OptimizedRouter");
        }
    }

    #[tokio::test]
    async fn group_middleware_runs_before_group_guards() {
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = Router::new();
        RouteGroup::new()
            .middleware(Arc::new(Recorder(log.clone(), "middleware")))
            .guard(Box::new(Recorder(log.clone(), "guard")))
            .route(&mut router, HttpMethod::GET, "/x", ok_handler);

        let response = router
            .route(crate::HttpRequest::new("GET", "/x"))
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(*log.lock().unwrap(), vec!["middleware", "guard"]);
    }

    #[test]
    fn test_route_group_with_parent() {
        let parent = RouteGroup::new().prefix("/api");
        let child = RouteGroup::new().prefix("/v1").with_parent(&parent);

        assert_eq!(child.get_prefix(), "/api/v1");
        assert_eq!(child.apply_prefix("/users"), "/api/v1/users");
    }
}
