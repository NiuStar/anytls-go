package util

import "strings"

var (
	ProgramVersionName = "anytls/dev"
	ProgramCommit      = "unknown"
	ProgramBuildTime   = "unknown"
)

func normalizedMeta(value, fallback string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return fallback
	}
	return v
}

func VersionName() string {
	return normalizedMeta(ProgramVersionName, "anytls/dev")
}

func CommitID() string {
	return normalizedMeta(ProgramCommit, "unknown")
}

func BuildTime() string {
	return normalizedMeta(ProgramBuildTime, "unknown")
}

func BuildInfo() string {
	return VersionName() + " commit=" + CommitID() + " build=" + BuildTime()
}
