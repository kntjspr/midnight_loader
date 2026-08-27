export namespace config {
	
	export class BuildConfig {
	    shellcode_url: string;
	    xor_key: string;
	    injection_target: string;
	    edr_process_name: string;
	    freeze_time_ms: number;
	    enable_anti_vm: boolean;
	    enable_melt: boolean;
	    enable_startup: boolean;
	    enable_admin: boolean;
	    sleep_delay: boolean;
	    hide_directory: boolean;
	    startup_entry_name: string;
	    directory_name: string;
	    file_name: string;
	    output_path: string;

	    static createFrom(source: any = {}) {
	        return new BuildConfig(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.shellcode_url = source["shellcode_url"];
	        this.xor_key = source["xor_key"];
	        this.injection_target = source["injection_target"];
	        this.edr_process_name = source["edr_process_name"];
	        this.freeze_time_ms = source["freeze_time_ms"];
	        this.enable_anti_vm = source["enable_anti_vm"];
	        this.enable_melt = source["enable_melt"];
	        this.enable_startup = source["enable_startup"];
	        this.enable_admin = source["enable_admin"];
	        this.sleep_delay = source["sleep_delay"];
	        this.hide_directory = source["hide_directory"];
	        this.startup_entry_name = source["startup_entry_name"];
	        this.directory_name = source["directory_name"];
	        this.file_name = source["file_name"];
	        this.output_path = source["output_path"];
	    }
	}

}
