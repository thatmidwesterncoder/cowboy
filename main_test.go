package main

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type UnpackSuite struct {
	suite.Suite
}

func (s *UnpackSuite) TestUnpackReturnsFoobar() {
	input := "H4sIAAAAAAAAA0vLz09KLAIAlR/2ngYAAAA="
	expected := "foobar"

	result, err := unpack(input)
	s.Require().NoError(err)
	s.Equal(expected, string(result))
}

func TestUnpack(t *testing.T) {
	suite.Run(t, new(UnpackSuite))
}

type ExtractBlobsSuite struct {
	suite.Suite
}

func (s *ExtractBlobsSuite) TestExtractBlobsFromMiddleOfString() {
	// This is a base64-encoded gzip blob that should be extracted from the middle of a string
	blob := "H4sIAAAAAAAAA+xdbW/buLL+vr+C6JfdxanfncQxUOA6Tnua07cgaXc/FMGClmhba1nU6sVp9uD+9ztDUrJsyzIpyU25uD2aJc4kBwOZ4Zzw9FtRIPI8WYkoJ41ZwEJWbBiwU/jObMW+PmUBySIPQ9/trgXUcdjQUimAV8SSvyArRweh2QSO67d/Knb7p60Ot1Wr026nWF3MOx3yderj28+3ZEb1QGghw73CD2xp6es37CdIHogv6hffyVOSEI1KB04GsziJfOikPx3NP7w+pIvYYTh8OsdGdn2e25RdxgFMSOvlxNm28we"

	input := "some text before\nblah" + blob + "\nsome text after"

	result := extractBlobs(input)
	s.Require().Len(result, 1, "Expected exactly one blob to be extracted")
	s.Equal(blob, result[0], "Extracted blob should match the original blob string")
}

func TestExtractBlobs(t *testing.T) {
	suite.Run(t, new(ExtractBlobsSuite))
}
