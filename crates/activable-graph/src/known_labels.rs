//! Well-known graph schema node and edge labels.

/// Vertex labels defined in the production schema.
pub mod vertex_labels {
    pub const PRINCIPAL: &str = "Principal";
    pub const RESOURCE: &str = "Resource";
    pub const PERMISSION: &str = "Permission";
    pub const SERVICE_PRINCIPAL: &str = "ServicePrincipal";
    pub const FEDERATED_PROVIDER: &str = "FederatedProvider";
    pub const ACCESS_KEY: &str = "AccessKey";

    // TBD schema items (placeholder names for future development)
    pub const TBD_POLICY: &str = "TBDPolicy";
    pub const TBD_ROLE: &str = "TBDRole";
    pub const TBD_GROUP: &str = "TBDGroup";
    pub const TBD_ACCOUNT: &str = "TBDAccount";
    pub const TBD_ORGANIZATION: &str = "TBDOrganization";
    pub const TBD_RESOURCE_TYPE: &str = "TBDResourceType";
}

/// Edge labels defined in the production schema.
pub mod edge_labels {
    pub const ASSUME_ROLE: &str = "AssumeRole";
    pub const HAS_PERMISSION: &str = "HasPermission";
    pub const CAN_ACCESS: &str = "CanAccess";
}
