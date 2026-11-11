package cyclonedxhelpers

import (
	"fmt"
	"sort"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal/cyclonedxutil/helpers"
	"github.com/anchore/syft/syft/pkg"
)

// Evidence relationships (artifact.ContainsRelationship and artifact.EvidentByRelationship) have no
// first-class CycloneDX representation: the dependencies block only carries package dependency-of edges and has
// nowhere to attach a relationship category. They are instead carried as properties on the component at the
// source of each edge, one set of properties per edge:
//
//	<namespace>:<index>:type -> syft relationship type ("contains" or "evident-by")
//	<namespace>:<index>:to   -> BOM-Ref of the relationship target
//
// The component holding the properties is always the relationship source, so the edge direction is preserved
// along with its category and the original endpoint identifiers. Component properties are valid across every
// supported CycloneDX spec version, letting a decoder reconstruct the relationship verbatim.
const (
	toPropertySuffix   = ":to"
	typePropertySuffix = ":type"
)

// attachRelationshipProperties encodes the evidence relationships that cannot be represented in the
// CycloneDX dependencies block by attaching them to their source components. Dependency-of relationships stay
// in the dependencies block; ownership-by-file-overlap has no reversible representation and is dropped.
func attachRelationshipProperties(components *[]cyclonedx.Component, relationships []artifact.Relationship) {
	if components == nil {
		return
	}

	byRef := indexComponentsByBOMRef(*components)

	// group edges by their source BOM-Ref, then sort within each group for deterministic property indices
	edgesByFrom := map[string][]artifact.Relationship{}
	for _, r := range relationships {
		if !isEvidenceRelationship(r.Type) {
			continue
		}
		fromRef := edgeRef(r.From)
		if _, exists := byRef[fromRef]; !exists {
			continue
		}
		edgesByFrom[fromRef] = append(edgesByFrom[fromRef], r)
	}

	fromRefs := make([]string, 0, len(edgesByFrom))
	for ref := range edgesByFrom {
		fromRefs = append(fromRefs, ref)
	}
	sort.Strings(fromRefs)

	for _, fromRef := range fromRefs {
		edges := edgesByFrom[fromRef]
		sort.Slice(edges, func(i, j int) bool {
			left, right := edges[i], edges[j]
			switch strings.Compare(string(left.Type), string(right.Type)) {
			case -1:
				return true
			case 1:
				return false
			}
			return edgeRef(left.To) < edgeRef(right.To)
		})

		component := byRef[fromRef]
		properties := []cyclonedx.Property{}
		if component.Properties != nil {
			properties = append(properties, *component.Properties...)
		}
		for index, edge := range edges {
			prefix := fmt.Sprintf("%s:%d", helpers.RelationshipPropertyNamespace, index)
			properties = append(properties,
				cyclonedx.Property{Name: prefix + typePropertySuffix, Value: string(edge.Type)},
				cyclonedx.Property{Name: prefix + toPropertySuffix, Value: edgeRef(edge.To)},
			)
		}
		component.Properties = &properties
	}
}

func indexComponentsByBOMRef(components []cyclonedx.Component) map[string]*cyclonedx.Component {
	out := map[string]*cyclonedx.Component{}
	for i := range components {
		component := &components[i]
		if component.BOMRef != "" {
			out[component.BOMRef] = component
		}
		if component.Components != nil {
			for ref, nested := range indexComponentsByBOMRef(*component.Components) {
				out[ref] = nested
			}
		}
	}
	return out
}

func isEvidenceRelationship(ty artifact.RelationshipType) bool {
	switch ty {
	case artifact.ContainsRelationship, artifact.EvidentByRelationship:
		return true
	default:
		return false
	}
}

// edgeRef returns the BOM-Ref used for a relationship endpoint. Packages use the same BOM-Ref derivation as
// the encoded components, while file locations are identified by their coordinate ID, which is the BOM-Ref of
// the corresponding file component.
func edgeRef(endpoint artifact.Identifiable) string {
	switch value := endpoint.(type) {
	case pkg.Package:
		return helpers.DeriveBomRef(value)
	case file.Location:
		return string(value.Coordinates.ID())
	case file.Coordinates:
		return string(value.ID())
	default:
		return string(endpoint.ID())
	}
}
