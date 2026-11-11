package spdxjson

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/internal/testutil"
)

// TestEvidenceRelationshipsRoundTrip verifies the three-package/two-evidence-kind fixture keeps every contains
// and evident-by edge, with direction, category and endpoints intact, through SPDX JSON encode -> decode on
// every supported SPDX version.
func TestEvidenceRelationshipsRoundTrip(t *testing.T) {
	input := testutil.EvidenceRelationshipsInput(t)

	for _, enc := range defaultFormatEncoders() {
		t.Run(enc.Version(), func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, enc.Encode(&buf, input))

			decoded, _, _, err := NewFormatDecoder().Decode(bytes.NewReader(buf.Bytes()))
			require.NoError(t, err, "encoded document:\n%s", buf.String())

			assert.ElementsMatch(t,
				testutil.EvidenceRelationshipExpectedLabels(),
				testutil.EvidenceRelationshipLabels(*decoded))

			var deps int
			for _, r := range decoded.Relationships {
				if r.Type == artifact.DependencyOfRelationship {
					deps++
				}
			}
			assert.Equal(t, 1, deps, "the unrelated dependency-of edge must be preserved")
		})
	}
}

// TestEvidenceRelationshipsCrossFormat proves the evidence edges survive a handoff between CycloneDX and
// SPDX in both directions, which is the round-trip the SBOM交接 bug report is about.
func TestEvidenceRelationshipsCrossFormat(t *testing.T) {
	input := testutil.EvidenceRelationshipsInput(t)
	want := testutil.EvidenceRelationshipExpectedLabels()

	t.Run("cyclonedx to spdx", func(t *testing.T) {
		cdxEncoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
		require.NoError(t, err)

		var cdxBuf bytes.Buffer
		require.NoError(t, cdxEncoder.Encode(&cdxBuf, input))

		fromCDX, _, _, err := cyclonedxjson.NewFormatDecoder().Decode(bytes.NewReader(cdxBuf.Bytes()))
		require.NoError(t, err)

		spdxEncoder, err := NewFormatEncoderWithConfig(DefaultEncoderConfig())
		require.NoError(t, err)

		var spdxBuf bytes.Buffer
		require.NoError(t, spdxEncoder.Encode(&spdxBuf, *fromCDX))

		decoded, _, _, err := NewFormatDecoder().Decode(bytes.NewReader(spdxBuf.Bytes()))
		require.NoError(t, err, "spdx document:\n%s", spdxBuf.String())

		assert.ElementsMatch(t, want, testutil.EvidenceRelationshipLabels(*decoded))
	})

	t.Run("spdx to cyclonedx", func(t *testing.T) {
		spdxEncoder, err := NewFormatEncoderWithConfig(DefaultEncoderConfig())
		require.NoError(t, err)

		var spdxBuf bytes.Buffer
		require.NoError(t, spdxEncoder.Encode(&spdxBuf, input))

		fromSPDX, _, _, err := NewFormatDecoder().Decode(bytes.NewReader(spdxBuf.Bytes()))
		require.NoError(t, err)

		cdxEncoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
		require.NoError(t, err)

		var cdxBuf bytes.Buffer
		require.NoError(t, cdxEncoder.Encode(&cdxBuf, *fromSPDX))

		decoded, _, _, err := cyclonedxjson.NewFormatDecoder().Decode(bytes.NewReader(cdxBuf.Bytes()))
		require.NoError(t, err, "cyclonedx document:\n%s", cdxBuf.String())

		assert.ElementsMatch(t, want, testutil.EvidenceRelationshipLabels(*decoded))
	})
}
