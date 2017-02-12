package main

type HijackerOptions struct {
	SourceDevice string            `yaml:"source_device"`
	TargetDevice string            `yaml:"target_device"`
	Targets      []*HijackerTarget `yaml:"targets"`
}

type HijackerTarget struct {
	Matches []string `yaml:"matches"`
	Address string   `yaml:"address"`
}
