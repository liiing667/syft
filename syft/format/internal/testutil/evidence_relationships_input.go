package testutil

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal/cyclonedxutil/helpers"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// EvidenceRelationshipsInput builds a deterministic SBOM with three packages and the two evidence edge
// categories (contains and evident-by), including both package-to-package and package-to-file endpoints.
// It is the shared fixture for cross-format (CycloneDX <-> SPDX) round-trip tests of evidence edges.
func EvidenceRelationshipsInput(t testing.TB) sbom.SBOM {
	t.Helper()

	lockfile := file.NewLocation("/opt/app/package-lock.json")
	buildArtifact := file.NewLocation("/opt/app/dist/app.bin")

	p1 := pkg.Package{
		Name:    "root-lib",
		Version: "1.0.0",
		Type:    pkg.NpmPkg,
		PURL:    "pkg:npm/root-lib@1.0.0",
	}
	p2 := pkg.Package{
		Name:    "nested-lib",
		Version: "2.3.4",
		Type:    pkg.NpmPkg,
		PURL:    "pkg:npm/nested-lib@2.3.4",
	}
	p3 := pkg.Package{
		Name:    "evident-lib",
		Version: "0.9.1",
		Type:    pkg.NpmPkg,
		PURL:    "pkg:npm/evident-lib@0.9.1",
	}
	for _, p := range []*pkg.Package{&p1, &p2, &p3} {
		p.SetID()
	}

	coordinates := []file.Coordinates{lockfile.Coordinates, buildArtifact.Coordinates}
	metadata := make(map[file.Coordinates]file.Metadata, len(coordinates))
	digests := make(map[file.Coordinates][]file.Digest, len(coordinates))
	for _, c := range coordinates {
		metadata[c] = file.Metadata{Path: c.RealPath}
		digests[c] = []file.Digest{{Algorithm: "sha256", Value: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}}
	}

	relationships := []artifact.Relationship{
		// package contains package
		{From: p1, To: p2, Type: artifact.ContainsRelationship},
		// package contains a build artifact (file endpoint)
		{From: p1, To: buildArtifact.Coordinates, Type: artifact.ContainsRelationship},
		// package existence is evident by the lockfile (file endpoint)
		{From: p2, To: lockfile.Coordinates, Type: artifact.EvidentByRelationship},
		// package existence is evident by the build artifact (file endpoint)
		{From: p3, To: buildArtifact.Coordinates, Type: artifact.EvidentByRelationship},
		// unrelated package dependency, which must keep using the CycloneDX dependencies block
		{From: p2, To: p1, Type: artifact.DependencyOfRelationship},
	}

	s := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:     pkg.NewCollection(p1, p2, p3),
			FileMetadata: metadata,
			FileDigests:  digests,
		},
		Relationships: relationships,
	}

	require.NotEmpty(t, s.Relationships)
	return s
}

// EvidenceRelationships returns the relationships expected to survive an evidence-edge round-trip, keyed by
// a stable "type/from/to" label so tests can compare without depending on endpoint concrete types.
func EvidenceRelationships(s sbom.SBOM) []string {
	var out []string
	for _, r := range s.Relationships {
		if r.Type != artifact.ContainsRelationship && r.Type != artifact.EvidentByRelationship {
			continue
		}
		out = append(out, string(r.Type)+"|"+string(r.From.ID())+"|"+string(r.To.ID()))
	}
	return out
}

// EvidenceRelationshipLabels renders the evidence edges of an SBOM as stable "type|from|to" labels that do not
// depend on syft package ID values. Package endpoints are labeled by their name and file endpoints by their
// coordinates, so edges remain comparable after a decode re-derives artifact IDs (e.g. adopting a BOM-Ref).
func EvidenceRelationshipLabels(s sbom.SBOM) []string {
	var out []string
	for _, r := range s.Relationships {
		if r.Type != artifact.ContainsRelationship && r.Type != artifact.EvidentByRelationship {
			continue
		}
		if p, ok := r.From.(pkg.Package); ok && p.Name == "unknown" {
			// SPDX 3.0 synthesizes a root "unknown" package that contains every element; these edges are
			// document-root bookkeeping, not evidence edges from the input SBOM
			continue
		}
		out = append(out, string(r.Type)+"|"+EvidenceEndpointLabel(r.From)+"|"+EvidenceEndpointLabel(r.To))
	}
	return out
}

// EvidenceEndpointLabel returns a stable, human-readable label for a relationship endpoint.
func EvidenceEndpointLabel(endpoint artifact.Identifiable) string {
	switch value := endpoint.(type) {
	case pkg.Package:
		return "package:" + value.Name
	case file.Location:
		return "file:" + normalizeEvidencePath(value.Coordinates.FullNestedPath())
	case file.Coordinates:
		return "file:" + normalizeEvidencePath(value.FullNestedPath())
	default:
		return "id:" + string(endpoint.ID())
	}
}

// normalizeEvidencePath removes the leading slash SPDX uses relative file names without, so the same file
// compares equal before and after an SPDX encode/decode hop.
func normalizeEvidencePath(path string) string {
	return strings.TrimPrefix(path, "/")
}

// EvidenceRelationshipExpectedLabels are the edges produced by EvidenceRelationshipsInput, expressed with the
// stable labels from EvidenceEndpointLabel.
func EvidenceRelationshipExpectedLabels() []string {
	return []string{
		"contains|package:root-lib|package:nested-lib",
		"contains|package:root-lib|file:opt/app/dist/app.bin",
		"evident-by|package:nested-lib|file:opt/app/package-lock.json",
		"evident-by|package:evident-lib|file:opt/app/dist/app.bin",
	}
}

// CycloneDXRelationshipPropertyNamespace re-exports the CycloneDX property namespace used to carry evidence
// edges so tests can assert on the serialized representation without importing the internal helpers directly.
const CycloneDXRelationshipPropertyNamespace = helpers.RelationshipPropertyNamespace
