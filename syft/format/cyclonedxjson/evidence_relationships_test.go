package cyclonedxjson

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/format/internal/testutil"
	"github.com/anchore/syft/syft/sbom"
)

// TestEvidenceRelationshipsRoundTrip verifies the three-package/two-evidence-kind fixture keeps every contains
// and evident-by edge, with direction, category and endpoint identifiers intact, through encode -> decode on
// every supported CycloneDX spec version.
func TestEvidenceRelationshipsRoundTrip(t *testing.T) {
	input := testutil.EvidenceRelationshipsInput(t)

	for _, enc := range defaultFormatEncoders() {
		t.Run(enc.Version(), func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, enc.Encode(&buf, input))

			decoded, _, _, err := NewFormatDecoder().Decode(bytes.NewReader(buf.Bytes()))
			require.NoError(t, err, "encoded document:\n%s", buf.String())

			if enc.Version() == "1.2" {
				// CycloneDX 1.2 has no component/BOM property mechanism, so evidence edges have no reversible
				// representation; they cannot be carried without violating the 1.2 schema. Dependency edges and
				// every component/BOM-Ref are still unaffected.
				assert.Empty(t, testutil.EvidenceRelationshipLabels(*decoded))
			} else {
				// edges are carried as namespaced component properties, never inside the dependencies block
				assert.Contains(t, buf.String(), testutil.CycloneDXRelationshipPropertyNamespace)
				assert.ElementsMatch(t,
					testutil.EvidenceRelationshipExpectedLabels(),
					testutil.EvidenceRelationshipLabels(*decoded))
			}
			assertDependencyEdgesUnchanged(t, &input, decoded)
		})
	}
}

func assertDependencyEdgesUnchanged(t *testing.T, input, decoded *sbom.SBOM) {
	t.Helper()
	var inputDeps, decodedDeps []string
	for _, r := range input.Relationships {
		if r.Type == artifact.DependencyOfRelationship {
			inputDeps = append(inputDeps, testutil.EvidenceEndpointLabel(r.From)+"->"+testutil.EvidenceEndpointLabel(r.To))
		}
	}
	for _, r := range decoded.Relationships {
		if r.Type == artifact.DependencyOfRelationship {
			decodedDeps = append(decodedDeps, testutil.EvidenceEndpointLabel(r.From)+"->"+testutil.EvidenceEndpointLabel(r.To))
		}
	}
	assert.ElementsMatch(t, inputDeps, decodedDeps)
}
