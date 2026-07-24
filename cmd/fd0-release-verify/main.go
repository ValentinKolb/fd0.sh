package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/valentinkolb/fd0.sh/internal/releaseverify"
)

var desktopTagPattern = regexp.MustCompile(`^desktop-v[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z][0-9A-Za-z.-]*)?$`)

func main() {
	bundlePath := flag.String("bundle", "", "Sigstore bundle path")
	tag := flag.String("tag", "", "Exact fd0 Desktop release tag")
	flag.Parse()
	if *bundlePath == "" || !desktopTagPattern.MatchString(*tag) || flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: fd0-release-verify --bundle FILE --tag desktop-vX.Y.Z MANIFEST\n")
		os.Exit(2)
	}
	identity := "https://github.com/ValentinKolb/fd0.sh/.github/workflows/release-desktop.yml@refs/tags/" + *tag
	if err := releaseverify.Verify(*bundlePath, flag.Arg(0), identity); err != nil {
		fmt.Fprintf(os.Stderr, "fd0 release verification failed: %v\n", err)
		os.Exit(1)
	}
}
