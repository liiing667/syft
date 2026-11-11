package helpers

// RelationshipPropertyNamespace is the prefix of the BOM-level properties that carry syft evidence
// relationships (contains and evident-by edges) which have no first-class CycloneDX representation.
//
// Each relationship is encoded as two properties on the source component, sharing one index:
//
//	<namespace>:<index>:type -> syft relationship type (e.g. "contains" or "evident-by")
//	<namespace>:<index>:to   -> BOM-Ref of the relationship target
//
// The component carrying the properties is the relationship source, so the encoding preserves the original
// direction, category and endpoint identifiers, allowing a decoder to reconstruct the relationship verbatim.
const RelationshipPropertyNamespace = "syft:relationship"

const (
	relationshipTypePropertySuffix = ":type"
	relationshipToPropertySuffix   = ":to"
)
