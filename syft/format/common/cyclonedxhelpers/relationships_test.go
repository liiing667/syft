package cyclonedxhelpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal/cyclonedxutil/helpers"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func sbomWithEdges(t *testing.T, packages []*pkg.Package, coordinates []file.Coordinates,
	relationships []artifact.Relationship,
) sbom.SBOM {
	t.Helper()
	metadata := map[file.Coordinates]file.Metadata{}
	for _, c := range coordinates {
		metadata[c] = file.Metadata{Path: c.RealPath}
	}
	values := make([]pkg.Package, 0, len(packages))
	for _, p := range packages {
		values = append(values, *p)
	}
	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:     pkg.NewCollection(values...),
			FileMetadata: metadata,
		},
		Relationships: relationships,
	}
}

func evidenceRelationshipsFixture() (p1, p2, p3 pkg.Package, lockfile, buildArtifact file.Location) {
	lockfile = file.NewLocation("/opt/app/package-lock.json")
	buildArtifact = file.NewLocation("/opt/app/dist/app.bin")

	p1 = pkg.Package{Name: "root-lib", PURL: "pkg:npm/root-lib@1.0.0"}
	p2 = pkg.Package{Name: "nested-lib", PURL: "pkg:npm/nested-lib@2.3.4"}
	p3 = pkg.Package{Name: "evident-lib", PURL: "pkg:npm/evident-lib@0.9.1"}
	for _, p := range []*pkg.Package{&p1, &p2, &p3} {
		p.SetID()
	}
	return p1, p2, p3, lockfile, buildArtifact
}

func Test_attachRelationshipProperties_threePackagesTwoEvidenceKinds(t *testing.T) {
	p1, p2, p3, lockfile, buildArtifact := evidenceRelationshipsFixture()

	relationships := []artifact.Relationship{
		{From: p1, To: p2, Type: artifact.ContainsRelationship},
		{From: p1, To: buildArtifact.Coordinates, Type: artifact.ContainsRelationship},
		{From: p2, To: lockfile.Coordinates, Type: artifact.EvidentByRelationship},
		{From: p3, To: buildArtifact.Coordinates, Type: artifact.EvidentByRelationship},
		// dependency-of edges must stay in the dependencies block, never become properties
		{From: p2, To: p1, Type: artifact.DependencyOfRelationship},
		// ownership edges have no reversible representation and remain dropped
		{From: p1, To: p3, Type: artifact.OwnershipByFileOverlapRelationship},
	}

	bom := ToFormatModel(sbomWithEdges(t, []*pkg.Package{&p1, &p2, &p3},
		[]file.Coordinates{lockfile.Coordinates, buildArtifact.Coordinates}, relationships))

	propertiesByRef := map[string][]cyclonedx.Property{}
	var walk func(components []cyclonedx.Component)
	walk = func(components []cyclonedx.Component) {
		for _, c := range components {
			if c.Properties != nil {
				var edgeProps []cyclonedx.Property
				for _, property := range *c.Properties {
					if property.Name != "syft:package:type" {
						edgeProps = append(edgeProps, property)
					}
				}
				propertiesByRef[c.BOMRef] = edgeProps
			}
			if c.Components != nil {
				walk(*c.Components)
			}
		}
	}
	walk(*bom.Components)

	// p1 sources two contains edges, sorted by target BOM-Ref (file ref < purl ref)
	assert.Equal(t, []cyclonedx.Property{
		{Name: "syft:relationship:0:type", Value: "contains"},
		{Name: "syft:relationship:0:to", Value: string(buildArtifact.Coordinates.ID())},
		{Name: "syft:relationship:1:type", Value: "contains"},
		{Name: "syft:relationship:1:to", Value: helpers.DeriveBomRef(p2)},
	}, propertiesByRef[helpers.DeriveBomRef(p1)])

	// p2 sources one evident-by edge to the lockfile
	assert.Equal(t, []cyclonedx.Property{
		{Name: "syft:relationship:0:type", Value: "evident-by"},
		{Name: "syft:relationship:0:to", Value: string(lockfile.Coordinates.ID())},
	}, propertiesByRef[helpers.DeriveBomRef(p2)])

	// p3 sources one evident-by edge to the build artifact
	assert.Equal(t, []cyclonedx.Property{
		{Name: "syft:relationship:0:type", Value: "evident-by"},
		{Name: "syft:relationship:0:to", Value: string(buildArtifact.Coordinates.ID())},
	}, propertiesByRef[helpers.DeriveBomRef(p3)])

	// no edges land on file components, and the BOM itself carries no relationship properties
	assert.Nil(t, bom.Properties)
	for _, c := range *bom.Components {
		if c.Type == cyclonedx.ComponentTypeFile {
			if c.Properties == nil {
				continue
			}
			for _, property := range *c.Properties {
				assert.NotContains(t, property.Name, helpers.RelationshipPropertyNamespace)
			}
		}
	}
}

func Test_evidenceEdgesRoundTripThroughCycloneDX(t *testing.T) {
	p1, p2, p3, lockfile, buildArtifact := evidenceRelationshipsFixture()

	original := []artifact.Relationship{
		{From: p1, To: p2, Type: artifact.ContainsRelationship},
		{From: p1, To: buildArtifact.Coordinates, Type: artifact.ContainsRelationship},
		{From: p2, To: lockfile.Coordinates, Type: artifact.EvidentByRelationship},
		{From: p3, To: buildArtifact.Coordinates, Type: artifact.EvidentByRelationship},
		{From: p2, To: p1, Type: artifact.DependencyOfRelationship},
	}

	bom := ToFormatModel(sbomWithEdges(t, []*pkg.Package{&p1, &p2, &p3},
		[]file.Coordinates{lockfile.Coordinates, buildArtifact.Coordinates}, original))

	decoded, err := helpers.ToSyftModel(bom)
	require.NoError(t, err)

	got := map[string]artifact.Relationship{}
	for _, r := range decoded.Relationships {
		got[string(r.Type)+"|"+string(r.From.ID())+"|"+string(r.To.ID())] = r
	}

	for _, want := range original {
		key := string(want.Type) + "|" + edgeRef(want.From) + "|" + edgeRef(want.To)
		actual, ok := got[key]
		require.True(t, ok, "missing round-tripped relationship: %s", key)
		assert.Equal(t, want.Type, actual.Type)
		assert.Equal(t, edgeRef(want.From), string(actual.From.ID()))
		assert.Equal(t, edgeRef(want.To), string(actual.To.ID()))
	}
	assert.Len(t, decoded.Relationships, len(original))
}

func Test_attachRelationshipProperties_nestedArchiveFileSource(t *testing.T) {
	// a file (archive) can itself be the source of a contains edge to an entry file
	archive := file.NewLocation("/app.war")
	entry := file.Location{
		LocationData: file.LocationData{
			Coordinates: file.Coordinates{RealPath: "/app.war", FullPath: "/app.war!/WEB-INF/lib/a.jar"},
		},
	}

	relationships := []artifact.Relationship{
		{From: archive.Coordinates, To: entry.Coordinates, Type: artifact.ContainsRelationship},
	}

	metadata := map[file.Coordinates]file.Metadata{
		archive.Coordinates: {Path: "/app.war"},
		entry.Coordinates:   {Path: "/app.war!/WEB-INF/lib/a.jar"},
	}
	input := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:     pkg.NewCollection(),
			FileMetadata: metadata,
		},
		Relationships: relationships,
	}

	bom := ToFormatModel(input)
	require.NotNil(t, bom.Components)

	var archiveProps []cyclonedx.Property
	var walk func(components []cyclonedx.Component)
	walk = func(components []cyclonedx.Component) {
		for _, c := range components {
			if c.BOMRef == string(archive.Coordinates.ID()) && c.Properties != nil {
				archiveProps = *c.Properties
			}
			if c.Components != nil {
				walk(*c.Components)
			}
		}
	}
	walk(*bom.Components)

	assert.Equal(t, []cyclonedx.Property{
		{Name: "syft:relationship:0:type", Value: "contains"},
		{Name: "syft:relationship:0:to", Value: string(entry.Coordinates.ID())},
	}, archiveProps)

	decoded, err := helpers.ToSyftModel(bom)
	require.NoError(t, err)

	var found bool
	for _, r := range decoded.Relationships {
		if r.Type == artifact.ContainsRelationship &&
			r.From.ID() == archive.Coordinates.ID() &&
			r.To.ID() == entry.Coordinates.ID() {
			found = true
		}
	}
	assert.True(t, found, "archive -> entry contains edge should round-trip")
}
