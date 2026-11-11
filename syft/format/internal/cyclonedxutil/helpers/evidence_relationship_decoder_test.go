package helpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func relationshipPackage(name, bomRef string) pkg.Package {
	p := pkg.Package{Name: name}
	p.OverrideID(artifact.ID(bomRef))
	return p
}

func Test_collectEvidenceRelationships(t *testing.T) {
	lockfile := file.NewCoordinates("/opt/app/package-lock.json", "")
	buildArtifact := file.NewCoordinates("/opt/app/dist/app.bin", "")

	idMap := map[string]any{
		"pkg:npm/root-lib@1.0.0":   relationshipPackage("root-lib", "pkg:npm/root-lib@1.0.0"),
		"pkg:npm/nested-lib@2.3.4": relationshipPackage("nested-lib", "pkg:npm/nested-lib@2.3.4"),
		string(lockfile.ID()):      lockfile,
		string(buildArtifact.ID()): buildArtifact,
	}

	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{
				BOMRef: "pkg:npm/root-lib@1.0.0",
				Type:   cyclonedx.ComponentTypeLibrary,
				Name:   "root-lib",
				Properties: &[]cyclonedx.Property{
					{Name: "syft:relationship:0:type", Value: "contains"},
					{Name: "syft:relationship:0:to", Value: "pkg:npm/nested-lib@2.3.4"},
					// missing :to companion -> skipped
					{Name: "syft:relationship:1:type", Value: "contains"},
					// unrecognized type -> skipped
					{Name: "syft:relationship:2:type", Value: "made-up"},
					{Name: "syft:relationship:2:to", Value: string(buildArtifact.ID())},
					// unresolvable target -> skipped
					{Name: "syft:relationship:3:type", Value: "contains"},
					{Name: "syft:relationship:3:to", Value: "missing-bom-ref"},
					// foreign namespace and unrelated package property -> ignored
					{Name: "other-tool:relationship:0:type", Value: "contains"},
					{Name: "syft:package:type", Value: "npm"},
				},
			},
			{
				BOMRef: "pkg:npm/nested-lib@2.3.4",
				Type:   cyclonedx.ComponentTypeLibrary,
				Name:   "nested-lib",
				Properties: &[]cyclonedx.Property{
					{Name: "syft:relationship:0:type", Value: "evident-by"},
					{Name: "syft:relationship:0:to", Value: string(lockfile.ID())},
				},
			},
			{
				BOMRef: string(buildArtifact.ID()),
				Type:   cyclonedx.ComponentTypeFile,
				Name:   "/opt/app/dist/app.bin",
			},
		},
	}

	got := collectEvidenceRelationships(bom, idMap)

	require.Len(t, got, 2)
	assert.Equal(t, artifact.ContainsRelationship, got[0].Type)
	assert.Equal(t, "pkg:npm/root-lib@1.0.0", string(got[0].From.ID()))
	assert.Equal(t, "pkg:npm/nested-lib@2.3.4", string(got[0].To.ID()))
	assert.Equal(t, artifact.EvidentByRelationship, got[1].Type)
	assert.Equal(t, "pkg:npm/nested-lib@2.3.4", string(got[1].From.ID()))
	assert.Equal(t, lockfile, got[1].To)
}

func Test_parseRelationshipPropertyName(t *testing.T) {
	tests := []struct {
		name      string
		wantIndex string
		wantField string
		wantOk    bool
	}{
		{name: "syft:relationship:0:type", wantIndex: "0", wantField: ":type", wantOk: true},
		{name: "syft:relationship:12:to", wantIndex: "12", wantField: ":to", wantOk: true},
		{name: "syft:package:type", wantOk: false},
		{name: "other:relationship:0:type", wantOk: false},
		{name: "syft:relationship:type", wantOk: false},
		{name: "syft:relationship:0:", wantOk: false},
		{name: "syft:relationship:0:from", wantOk: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index, field, ok := parseRelationshipPropertyName(tt.name)
			assert.Equal(t, tt.wantOk, ok)
			if ok {
				assert.Equal(t, tt.wantIndex, index)
				assert.Equal(t, tt.wantField, field)
			}
		})
	}
}
