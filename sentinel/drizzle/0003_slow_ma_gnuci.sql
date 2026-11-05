CREATE TABLE `commander_documents` (
	`id` text PRIMARY KEY NOT NULL,
	`kind` text NOT NULL,
	`incident_id` text,
	`title` text NOT NULL,
	`body` text NOT NULL,
	`status` text NOT NULL,
	`revision` integer DEFAULT 1 NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`incident_id`) REFERENCES `incidents`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE TABLE `commander_sessions` (
	`token_hash` text PRIMARY KEY NOT NULL,
	`workspace_hash` text NOT NULL,
	`expires_at` integer NOT NULL,
	FOREIGN KEY (`workspace_hash`) REFERENCES `sessions`(`token_hash`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `commander_sessions_workspace_idx` ON `commander_sessions` (`workspace_hash`);