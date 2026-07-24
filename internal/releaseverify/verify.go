package releaseverify

import (
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const githubOIDCIssuer = "https://token.actions.githubusercontent.com"

// Verify authenticates an artifact against a Sigstore bundle and an exact
// certificate identity. Trust roots are obtained through Sigstore's TUF client
// so root rotation does not require an fd0 release.
func Verify(bundlePath, artifactPath, expectedIdentity string) error {
	signedBundle, err := bundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return fmt.Errorf("load Sigstore bundle: %w", err)
	}

	client, err := tuf.New(tuf.DefaultOptions())
	if err != nil {
		return fmt.Errorf("initialize Sigstore trust: %w", err)
	}
	trustedRootJSON, err := client.GetTarget("trusted_root.json")
	if err != nil {
		return fmt.Errorf("load Sigstore trusted root: %w", err)
	}
	trustedRoot, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return fmt.Errorf("parse Sigstore trusted root: %w", err)
	}

	identity, err := verify.NewShortCertificateIdentity(
		githubOIDCIssuer,
		"",
		expectedIdentity,
		"",
	)
	if err != nil {
		return fmt.Errorf("build release identity policy: %w", err)
	}
	verifier, err := verify.NewVerifier(
		trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithObserverTimestamps(1),
		verify.WithTransparencyLog(1),
	)
	if err != nil {
		return fmt.Errorf("initialize Sigstore verifier: %w", err)
	}

	artifact, err := os.Open(artifactPath)
	if err != nil {
		return fmt.Errorf("open release manifest: %w", err)
	}
	defer artifact.Close()

	_, err = verifier.Verify(signedBundle, verify.NewPolicy(
		verify.WithArtifact(artifact),
		verify.WithCertificateIdentity(identity),
	))
	if err != nil {
		return fmt.Errorf("authenticate release manifest: %w", err)
	}
	return nil
}
