package web

import "embed"

// Files embeds only production assets; Go sources and tests never enter the UI.
//
//go:embed *.html *.css *.js *.svg vendor/*
var Files embed.FS
